rule TTP_XOR_QUAD_CurrentVersionRun_1321 {
  strings:
    $key_1321 = { 40 4e [2] 64 40 [2] 4f 6c [2] 61 4e [2] 75 55 [2] 7a 4f [2] 64 52 [2] 66 53 [2] 7d 55 [2] 61 52 [2] 7d 7d }

  condition:
    any of them
}