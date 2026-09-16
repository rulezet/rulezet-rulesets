rule TTP_XOR_QUAD_CurrentVersionRun_dc51 {
  strings:
    $key_dc51 = { 8f 3e [2] ab 30 [2] 80 1c [2] ae 3e [2] ba 25 [2] b5 3f [2] ab 22 [2] a9 23 [2] b2 25 [2] ae 22 [2] b2 0d }

  condition:
    any of them
}