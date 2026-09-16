rule TTP_XOR_QUAD_CurrentVersionRun_c50b {
  strings:
    $key_c50b = { 96 64 [2] b2 6a [2] 99 46 [2] b7 64 [2] a3 7f [2] ac 65 [2] b2 78 [2] b0 79 [2] ab 7f [2] b7 78 [2] ab 57 }

  condition:
    any of them
}