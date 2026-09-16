rule TTP_XOR_QUAD_CurrentVersionRun_2121 {
  strings:
    $key_2121 = { 72 4e [2] 56 40 [2] 7d 6c [2] 53 4e [2] 47 55 [2] 48 4f [2] 56 52 [2] 54 53 [2] 4f 55 [2] 53 52 [2] 4f 7d }

  condition:
    any of them
}