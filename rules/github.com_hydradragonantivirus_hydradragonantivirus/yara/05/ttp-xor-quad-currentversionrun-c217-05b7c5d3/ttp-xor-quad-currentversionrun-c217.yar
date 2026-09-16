rule TTP_XOR_QUAD_CurrentVersionRun_c217 {
  strings:
    $key_c217 = { 91 78 [2] b5 76 [2] 9e 5a [2] b0 78 [2] a4 63 [2] ab 79 [2] b5 64 [2] b7 65 [2] ac 63 [2] b0 64 [2] ac 4b }

  condition:
    any of them
}