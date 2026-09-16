rule APT28_IMPLANT_1_v3
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
      $rol7encode = { 0F B7 C9 C1 C0 07 83 C2 02 33 C1 0F B7 0A 47 66 85 C9 75 }
condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}