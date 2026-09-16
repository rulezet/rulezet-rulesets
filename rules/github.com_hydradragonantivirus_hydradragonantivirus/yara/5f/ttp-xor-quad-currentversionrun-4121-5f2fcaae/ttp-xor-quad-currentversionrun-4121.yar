rule TTP_XOR_QUAD_CurrentVersionRun_4121 {
  strings:
    $key_4121 = { 12 4e [2] 36 40 [2] 1d 6c [2] 33 4e [2] 27 55 [2] 28 4f [2] 36 52 [2] 34 53 [2] 2f 55 [2] 33 52 [2] 2f 7d }

  condition:
    any of them
}