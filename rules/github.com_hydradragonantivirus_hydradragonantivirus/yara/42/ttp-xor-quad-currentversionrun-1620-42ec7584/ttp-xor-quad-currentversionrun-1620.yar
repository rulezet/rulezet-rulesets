rule TTP_XOR_QUAD_CurrentVersionRun_1620 {
  strings:
    $key_1620 = { 45 4f [2] 61 41 [2] 4a 6d [2] 64 4f [2] 70 54 [2] 7f 4e [2] 61 53 [2] 63 52 [2] 78 54 [2] 64 53 [2] 78 7c }

  condition:
    any of them
}