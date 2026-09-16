rule TTP_XOR_QUAD_CurrentVersionRun_0921 {
  strings:
    $key_0921 = { 5a 4e [2] 7e 40 [2] 55 6c [2] 7b 4e [2] 6f 55 [2] 60 4f [2] 7e 52 [2] 7c 53 [2] 67 55 [2] 7b 52 [2] 67 7d }

  condition:
    any of them
}