rule TTP_XOR_QUAD_CurrentVersionRun_3201 {
  strings:
    $key_3201 = { 61 6e [2] 45 60 [2] 6e 4c [2] 40 6e [2] 54 75 [2] 5b 6f [2] 45 72 [2] 47 73 [2] 5c 75 [2] 40 72 [2] 5c 5d }

  condition:
    any of them
}