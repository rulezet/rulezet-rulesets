rule TTP_XOR_QUAD_CurrentVersionRun_3efe {
  strings:
    $key_3efe = { 6d 91 [2] 49 9f [2] 62 b3 [2] 4c 91 [2] 58 8a [2] 57 90 [2] 49 8d [2] 4b 8c [2] 50 8a [2] 4c 8d [2] 50 a2 }

  condition:
    any of them
}