rule VirusShareWin32HLLPNeshta {
  meta:
    description = "datamaliciousorder - file VirusShareWin32HLLPNeshta.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cf39c56e6e8807e619044a1cd553419fe085104bfd73bff36f7e799d3511ce4"

  strings:
    $s1  = "Error processing packet in round %d" fullword ascii
    $s2  = "Could not decode UPN sent by the server; target service name will not be used and Kerberos authentication will not work" fullword ascii
    $s3  = "Private key does not match the certificate public keySSL_CTX_set_default_verify_paths failed" fullword ascii
    $s4  = "Windows Authentication Plugin - client side" fullword ascii
    $s5  = "Could not obtain local credentials required for authentication" fullword ascii
    $s6  = "Handshake completed after %d rounds" fullword ascii
    $s7  = "This error probably means that your MySQL server doesn't support the" fullword ascii
    $s8  = "Error reading packet in round %d" fullword ascii
    $s9  = "Error reading initial packet" fullword ascii
    $s10 = "The protocol to use for connection (tcp, socket, pipe, memory)." fullword ascii
    $s11 = "unable to proccess private key, bad format" fullword ascii
    $s12 = "No data to send in round %d but handshake is not complete" fullword ascii
    $s13 = "Authentication handshake could not be completed after %d rounds" fullword ascii
    $s14 = "Windows Authentication Plugin %s: " fullword ascii
    $s15 = "Clear password authentication plugin" fullword ascii
    $s16 = "Failed to convert UPN to utf8" fullword ascii
    $s17 = "show keys from `" fullword ascii
    $s18 = "Error writing packet in round %d" fullword ascii
    $s19 = "Buffer overrun when determining UPN: need %ul characters but have %ul" fullword ascii
    $s20 = "Base name of shared memory." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}