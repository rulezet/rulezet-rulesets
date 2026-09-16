rule TTP_XOR_QUAD_CurrentVersionRun_3501 {
  strings:
    $key_3501 = { 66 6e [2] 42 60 [2] 69 4c [2] 47 6e [2] 53 75 [2] 5c 6f [2] 42 72 [2] 40 73 [2] 5b 75 [2] 47 72 [2] 5b 5d }

  condition:
    any of them
}