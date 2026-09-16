rule TTP_XOR_QUAD_CurrentVersionRun_1271 {
  strings:
    $key_1271 = { 41 1e [2] 65 10 [2] 4e 3c [2] 60 1e [2] 74 05 [2] 7b 1f [2] 65 02 [2] 67 03 [2] 7c 05 [2] 60 02 [2] 7c 2d }

  condition:
    any of them
}