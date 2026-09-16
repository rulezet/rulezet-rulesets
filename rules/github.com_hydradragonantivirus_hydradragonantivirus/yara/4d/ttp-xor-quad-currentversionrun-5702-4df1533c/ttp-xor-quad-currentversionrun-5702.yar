rule TTP_XOR_QUAD_CurrentVersionRun_5702 {
  strings:
    $key_5702 = { 04 6d [2] 20 63 [2] 0b 4f [2] 25 6d [2] 31 76 [2] 3e 6c [2] 20 71 [2] 22 70 [2] 39 76 [2] 25 71 [2] 39 5e }

  condition:
    any of them
}