rule TTP_XOR_QUAD_CurrentVersionRun_09e3 {
  strings:
    $key_09e3 = { 5a 8c [2] 7e 82 [2] 55 ae [2] 7b 8c [2] 6f 97 [2] 60 8d [2] 7e 90 [2] 7c 91 [2] 67 97 [2] 7b 90 [2] 67 bf }

  condition:
    any of them
}