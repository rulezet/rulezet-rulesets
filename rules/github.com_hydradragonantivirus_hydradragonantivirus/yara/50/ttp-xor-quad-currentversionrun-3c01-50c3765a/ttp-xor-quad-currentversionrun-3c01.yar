rule TTP_XOR_QUAD_CurrentVersionRun_3c01 {
  strings:
    $key_3c01 = { 6f 6e [2] 4b 60 [2] 60 4c [2] 4e 6e [2] 5a 75 [2] 55 6f [2] 4b 72 [2] 49 73 [2] 52 75 [2] 4e 72 [2] 52 5d }

  condition:
    any of them
}