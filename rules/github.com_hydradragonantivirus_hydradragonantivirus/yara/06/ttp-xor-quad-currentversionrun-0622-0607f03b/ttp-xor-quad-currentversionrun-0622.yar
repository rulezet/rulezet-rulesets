rule TTP_XOR_QUAD_CurrentVersionRun_0622 {
  strings:
    $key_0622 = { 55 4d [2] 71 43 [2] 5a 6f [2] 74 4d [2] 60 56 [2] 6f 4c [2] 71 51 [2] 73 50 [2] 68 56 [2] 74 51 [2] 68 7e }

  condition:
    any of them
}