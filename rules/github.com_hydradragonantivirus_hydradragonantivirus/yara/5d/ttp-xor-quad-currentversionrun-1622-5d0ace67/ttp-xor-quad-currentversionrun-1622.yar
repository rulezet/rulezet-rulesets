rule TTP_XOR_QUAD_CurrentVersionRun_1622 {
  strings:
    $key_1622 = { 45 4d [2] 61 43 [2] 4a 6f [2] 64 4d [2] 70 56 [2] 7f 4c [2] 61 51 [2] 63 50 [2] 78 56 [2] 64 51 [2] 78 7e }

  condition:
    any of them
}