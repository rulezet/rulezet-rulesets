rule TTP_XOR_QUAD_CurrentVersionRun_0912 {
  strings:
    $key_0912 = { 5a 7d [2] 7e 73 [2] 55 5f [2] 7b 7d [2] 6f 66 [2] 60 7c [2] 7e 61 [2] 7c 60 [2] 67 66 [2] 7b 61 [2] 67 4e }

  condition:
    any of them
}