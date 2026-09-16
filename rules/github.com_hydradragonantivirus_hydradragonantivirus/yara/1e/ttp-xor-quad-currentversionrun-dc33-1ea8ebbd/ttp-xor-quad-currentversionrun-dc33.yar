rule TTP_XOR_QUAD_CurrentVersionRun_dc33 {
  strings:
    $key_dc33 = { 8f 5c [2] ab 52 [2] 80 7e [2] ae 5c [2] ba 47 [2] b5 5d [2] ab 40 [2] a9 41 [2] b2 47 [2] ae 40 [2] b2 6f }

  condition:
    any of them
}