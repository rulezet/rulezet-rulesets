rule TTP_XOR_QUAD_CurrentVersionRun_38e3 {
  strings:
    $key_38e3 = { 6b 8c [2] 4f 82 [2] 64 ae [2] 4a 8c [2] 5e 97 [2] 51 8d [2] 4f 90 [2] 4d 91 [2] 56 97 [2] 4a 90 [2] 56 bf }

  condition:
    any of them
}