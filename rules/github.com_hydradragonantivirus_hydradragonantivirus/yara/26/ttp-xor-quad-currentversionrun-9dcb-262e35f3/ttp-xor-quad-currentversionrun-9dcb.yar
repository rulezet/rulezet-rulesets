rule TTP_XOR_QUAD_CurrentVersionRun_9dcb {
  strings:
    $key_9dcb = { ce a4 [2] ea aa [2] c1 86 [2] ef a4 [2] fb bf [2] f4 a5 [2] ea b8 [2] e8 b9 [2] f3 bf [2] ef b8 [2] f3 97 }

  condition:
    any of them
}