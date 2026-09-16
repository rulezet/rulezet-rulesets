rule this_alt_key {
  meta:
    author = "@tylabs"
    hash   = "821f7ef4349d542f5f34f90b10bcc690"

  strings:
    $a = { 79 BA 1E 6F E1 16 79 DF 32 88 FE 29 C9 ED 52 B6 13 4D B3 4C 73 D3 7B 72 D0 24 CF FD 57 FE C7 67 9E 52 7A D3 05 63 }

  condition:
    any of them
}