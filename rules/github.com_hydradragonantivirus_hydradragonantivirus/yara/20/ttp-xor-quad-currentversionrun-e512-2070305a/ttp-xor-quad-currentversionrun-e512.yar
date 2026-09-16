rule TTP_XOR_QUAD_CurrentVersionRun_e512 {
  strings:
    $key_e512 = { b6 7d [2] 92 73 [2] b9 5f [2] 97 7d [2] 83 66 [2] 8c 7c [2] 92 61 [2] 90 60 [2] 8b 66 [2] 97 61 [2] 8b 4e }

  condition:
    any of them
}