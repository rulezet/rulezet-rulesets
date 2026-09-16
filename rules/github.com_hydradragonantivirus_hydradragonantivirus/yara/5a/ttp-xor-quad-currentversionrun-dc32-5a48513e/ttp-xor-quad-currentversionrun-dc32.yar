rule TTP_XOR_QUAD_CurrentVersionRun_dc32 {
  strings:
    $key_dc32 = { 8f 5d [2] ab 53 [2] 80 7f [2] ae 5d [2] ba 46 [2] b5 5c [2] ab 41 [2] a9 40 [2] b2 46 [2] ae 41 [2] b2 6e }

  condition:
    any of them
}