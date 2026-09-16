import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_8_2_Virus_Hijac_343 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5847c0d50553d832c289b21658cf64bdae66267b2ef73b3751231791c076e525"
    hash2       = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"

  strings:
    $x1  = "<publisherIdentity name=\"CN=Google Inc, O=Google Inc, L=Mountain View, S=California, C=US\" issuerKeyHash=\"963b53f0793397af7d8" ascii
    $s2  = "e xmlns:r=\"urn:mpeg:mpeg21:2003:01-REL-R-NS\" xmlns:as=\"http://schemas.microsoft.com/windows/pki/2005/Authenticode\"><r:grant>" ascii
    $s3  = "  <asmv1:assemblyIdentity name=\"clickonce_bootstrap.exe\" version=\"1.3.33.17\" publicKeyToken=\"baa8013a79450f71\" language=\"" ascii
    $s4  = "  <file name=\"GoogleUpdateSetup.exe\" size=\"1130840\">" fullword ascii
    $s5  = "thm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"" ascii
    $s6  = "4n#\" /><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /><Reference URI=\"\"><Transforms><Transform A" ascii
    $s7  = "-sha1\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><Tran" ascii
    $s8  = "<asmv1:assembly xsi:schemaLocation=\"urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd\" manifestVersion=\"1.0\" xmlns:asmv" ascii
    $s9  = "<asmv1:assembly xsi:schemaLocation=\"urn:schemas-microsoft-com:asm.v1 assembly.adaptive.xsd\" manifestVersion=\"1.0\" xmlns:asmv" ascii
    $s10 = "View, S=California, C=US</as:X509SubjectName></as:AuthenticodePublisher></r:grant><r:issuer><Signature Id=\"AuthenticodeSignatur" ascii
    $s11 = "s3NIQ==</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>xA2CxEEpKOX9DD+lxw5mvaXEi7OKrIQDn4QuON8GsU79M2BYODbdIs/f8VAfR/F" ascii
    $s12 = "<publisherIdentity name=\"CN=Google Inc, O=Google Inc, L=Mountain View, S=California, C=US\" issuerKeyHash=\"963b53f0793397af7d8" ascii
    $s13 = "2e2bcccab7861e7266\" /><Signature Id=\"StrongNameSignature\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><Canonical" ascii
    $s14 = "zcZY5sYRdzLfut85SIrRJ9czd6jJ5F7t+hLP8/367quAhhM061p+b2wb7thLssx3mIesyvW7ZG9JHluRY1AfYy2DJ3MHnysW9HtxKQ==</Modulus><Exponent>AQAB" ascii
    $s15 = "Value></Reference></SignedInfo><SignatureValue>QSd/Qwz8ZcZ6tNKe7piOmh3tcI2G6xu1b/zRCBZKs4zhq3fNRzpHvEKWP2iEt81b2O/1KsINv3ct8GMxC" ascii
    $s16 = "</as:Timestamp></Object></Signature></r:issuer></r:license></msrel:RelData></KeyInfo></Signature></asmv1:assembly>" fullword ascii
    $s17 = "aERXRTl4r0nS1S+K4ReD6bDdAUK75fDiSKxH3fzvc1D1PFMqT+1i4SvZPLQFCE=</X509Certificate></X509Data></KeyInfo><Object><as:Timestamp>MIII" ascii
    $s18 = "RY1AfYy2DJ3MHnysW9HtxKQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue><X509Data><X509Certificate>MIIE3TCCA8WgAwIB" ascii
    $s19 = "  <application />" fullword ascii
    $s20 = "yValue><Modulus>xA2CxEEpKOX9DD+lxw5mvaXEi7OKrIQDn4QuON8GsU79M2BYODbdIs/f8VAfR/FVBcGBAecoPv9fiRIJ6t+qF0kscatI0Z0u9FHgA+D3Fmx7DCJ1" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}