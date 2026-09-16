rule TTP_XOR_QUAD_CurrentVersionRun_0e01 {
  strings:
    $key_0e01 = { 5d 6e [2] 79 60 [2] 52 4c [2] 7c 6e [2] 68 75 [2] 67 6f [2] 79 72 [2] 7b 73 [2] 60 75 [2] 7c 72 [2] 60 5d }

  condition:
    any of them
}