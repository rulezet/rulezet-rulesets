rule TTP_XOR_QUAD_CurrentVersionRun_e530 {
  strings:
    $key_e530 = { b6 5f [2] 92 51 [2] b9 7d [2] 97 5f [2] 83 44 [2] 8c 5e [2] 92 43 [2] 90 42 [2] 8b 44 [2] 97 43 [2] 8b 6c }

  condition:
    any of them
}