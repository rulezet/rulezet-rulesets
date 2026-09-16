rule TTP_XOR_QUAD_CurrentVersionRun_c527 {
  strings:
    $key_c527 = { 96 48 [2] b2 46 [2] 99 6a [2] b7 48 [2] a3 53 [2] ac 49 [2] b2 54 [2] b0 55 [2] ab 53 [2] b7 54 [2] ab 7b }

  condition:
    any of them
}