rule TTP_XOR_QUAD_CurrentVersionRun_36e3 {
  strings:
    $key_36e3 = { 65 8c [2] 41 82 [2] 6a ae [2] 44 8c [2] 50 97 [2] 5f 8d [2] 41 90 [2] 43 91 [2] 58 97 [2] 44 90 [2] 58 bf }

  condition:
    any of them
}