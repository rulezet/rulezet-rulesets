rule TTP_XOR_QUAD_CurrentVersionRun_6212 {
  strings:
    $key_6212 = { 31 7d [2] 15 73 [2] 3e 5f [2] 10 7d [2] 04 66 [2] 0b 7c [2] 15 61 [2] 17 60 [2] 0c 66 [2] 10 61 [2] 0c 4e }

  condition:
    any of them
}