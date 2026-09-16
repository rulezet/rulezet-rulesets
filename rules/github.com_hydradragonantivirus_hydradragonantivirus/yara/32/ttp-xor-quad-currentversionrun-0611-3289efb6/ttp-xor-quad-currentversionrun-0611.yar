rule TTP_XOR_QUAD_CurrentVersionRun_0611 {
  strings:
    $key_0611 = { 55 7e [2] 71 70 [2] 5a 5c [2] 74 7e [2] 60 65 [2] 6f 7f [2] 71 62 [2] 73 63 [2] 68 65 [2] 74 62 [2] 68 4d }

  condition:
    any of them
}