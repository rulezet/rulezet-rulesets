rule TTP_XOR_QUAD_CurrentVersionRun_6921 {
  strings:
    $key_6921 = { 3a 4e [2] 1e 40 [2] 35 6c [2] 1b 4e [2] 0f 55 [2] 00 4f [2] 1e 52 [2] 1c 53 [2] 07 55 [2] 1b 52 [2] 07 7d }

  condition:
    any of them
}