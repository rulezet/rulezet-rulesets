rule TTP_XOR_QUAD_CurrentVersionRun_1632 {
  strings:
    $key_1632 = { 45 5d [2] 61 53 [2] 4a 7f [2] 64 5d [2] 70 46 [2] 7f 5c [2] 61 41 [2] 63 40 [2] 78 46 [2] 64 41 [2] 78 6e }

  condition:
    any of them
}