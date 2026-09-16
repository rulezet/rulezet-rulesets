rule TTP_XOR_QUAD_CurrentVersionRun_32e3 {
  strings:
    $key_32e3 = { 61 8c [2] 45 82 [2] 6e ae [2] 40 8c [2] 54 97 [2] 5b 8d [2] 45 90 [2] 47 91 [2] 5c 97 [2] 40 90 [2] 5c bf }

  condition:
    any of them
}