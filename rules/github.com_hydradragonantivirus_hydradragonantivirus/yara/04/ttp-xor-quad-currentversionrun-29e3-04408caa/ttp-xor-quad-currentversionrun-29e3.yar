rule TTP_XOR_QUAD_CurrentVersionRun_29e3 {
  strings:
    $key_29e3 = { 7a 8c [2] 5e 82 [2] 75 ae [2] 5b 8c [2] 4f 97 [2] 40 8d [2] 5e 90 [2] 5c 91 [2] 47 97 [2] 5b 90 [2] 47 bf }

  condition:
    any of them
}