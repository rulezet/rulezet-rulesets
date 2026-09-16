rule TTP_XOR_QUAD_CurrentVersionRun_19e3 {
  strings:
    $key_19e3 = { 4a 8c [2] 6e 82 [2] 45 ae [2] 6b 8c [2] 7f 97 [2] 70 8d [2] 6e 90 [2] 6c 91 [2] 77 97 [2] 6b 90 [2] 77 bf }

  condition:
    any of them
}