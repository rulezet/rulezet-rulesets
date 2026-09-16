rule TTP_XOR_QUAD_CurrentVersionRun_5002 {
  strings:
    $key_5002 = { 03 6d [2] 27 63 [2] 0c 4f [2] 22 6d [2] 36 76 [2] 39 6c [2] 27 71 [2] 25 70 [2] 3e 76 [2] 22 71 [2] 3e 5e }

  condition:
    any of them
}