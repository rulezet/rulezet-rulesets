rule TTP_XOR_QUAD_CurrentVersionRun_3202 {
  strings:
    $key_3202 = { 61 6d [2] 45 63 [2] 6e 4f [2] 40 6d [2] 54 76 [2] 5b 6c [2] 45 71 [2] 47 70 [2] 5c 76 [2] 40 71 [2] 5c 5e }

  condition:
    any of them
}