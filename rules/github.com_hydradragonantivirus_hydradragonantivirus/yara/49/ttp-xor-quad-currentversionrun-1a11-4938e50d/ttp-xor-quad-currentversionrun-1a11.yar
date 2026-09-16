rule TTP_XOR_QUAD_CurrentVersionRun_1a11 {
  strings:
    $key_1a11 = { 49 7e [2] 6d 70 [2] 46 5c [2] 68 7e [2] 7c 65 [2] 73 7f [2] 6d 62 [2] 6f 63 [2] 74 65 [2] 68 62 [2] 74 4d }

  condition:
    any of them
}