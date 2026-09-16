rule TTP_XOR_QUAD_CurrentVersionRun_f726 {
  strings:
    $key_f726 = { a4 49 [2] 80 47 [2] ab 6b [2] 85 49 [2] 91 52 [2] 9e 48 [2] 80 55 [2] 82 54 [2] 99 52 [2] 85 55 [2] 99 7a }

  condition:
    any of them
}