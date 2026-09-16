rule TTP_XOR_QUAD_CurrentVersionRun_1651 {
  strings:
    $key_1651 = { 45 3e [2] 61 30 [2] 4a 1c [2] 64 3e [2] 70 25 [2] 7f 3f [2] 61 22 [2] 63 23 [2] 78 25 [2] 64 22 [2] 78 0d }

  condition:
    any of them
}