rule TTP_XOR_QUAD_CurrentVersionRun_1efe {
  strings:
    $key_1efe = { 4d 91 [2] 69 9f [2] 42 b3 [2] 6c 91 [2] 78 8a [2] 77 90 [2] 69 8d [2] 6b 8c [2] 70 8a [2] 6c 8d [2] 70 a2 }

  condition:
    any of them
}