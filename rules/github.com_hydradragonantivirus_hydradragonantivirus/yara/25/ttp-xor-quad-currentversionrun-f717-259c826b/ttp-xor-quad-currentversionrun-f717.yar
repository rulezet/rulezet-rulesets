rule TTP_XOR_QUAD_CurrentVersionRun_f717 {
  strings:
    $key_f717 = { a4 78 [2] 80 76 [2] ab 5a [2] 85 78 [2] 91 63 [2] 9e 79 [2] 80 64 [2] 82 65 [2] 99 63 [2] 85 64 [2] 99 4b }

  condition:
    any of them
}