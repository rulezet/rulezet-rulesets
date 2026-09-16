rule TTP_XOR_QUAD_CurrentVersionRun_39e3 {
  strings:
    $key_39e3 = { 6a 8c [2] 4e 82 [2] 65 ae [2] 4b 8c [2] 5f 97 [2] 50 8d [2] 4e 90 [2] 4c 91 [2] 57 97 [2] 4b 90 [2] 57 bf }

  condition:
    any of them
}