rule TTP_XOR_QUAD_CurrentVersionRun_dc16 {
  strings:
    $key_dc16 = { 8f 79 [2] ab 77 [2] 80 5b [2] ae 79 [2] ba 62 [2] b5 78 [2] ab 65 [2] a9 64 [2] b2 62 [2] ae 65 [2] b2 4a }

  condition:
    any of them
}