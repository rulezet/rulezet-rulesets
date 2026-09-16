rule TTP_XOR_QUAD_CurrentVersionRun_12e3 {
  strings:
    $key_12e3 = { 41 8c [2] 65 82 [2] 4e ae [2] 60 8c [2] 74 97 [2] 7b 8d [2] 65 90 [2] 67 91 [2] 7c 97 [2] 60 90 [2] 7c bf }

  condition:
    any of them
}