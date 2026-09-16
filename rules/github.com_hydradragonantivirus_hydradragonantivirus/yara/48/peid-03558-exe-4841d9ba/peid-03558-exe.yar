rule PEiD_03558_______EXE______________________________ {
  meta:
    description = "Packer convert base64 to ascii wrLDmMK+wqjCuMOzRVhFw47DhMK8w77DgMKmwrDDs8K7w7ogwrvDocOUwrHDl8KowrDDpiAtPiDCs8OCwr7CrcOowro="
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 E4 53 56 57 33 C0 89 45 E4 89 45 }

  condition:
    $a
}