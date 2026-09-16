rule TTP_XOR_QUAD_CurrentVersionRun_62e3 {
  strings:
    $key_62e3 = { 31 8c [2] 15 82 [2] 3e ae [2] 10 8c [2] 04 97 [2] 0b 8d [2] 15 90 [2] 17 91 [2] 0c 97 [2] 10 90 [2] 0c bf }

  condition:
    any of them
}