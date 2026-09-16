rule fake_chrome_updater_dex_android {
  meta:
    description = "Fake Chrome updater classes*.dex (Android)"
    author = "Andras Gemes"
    date = "2025-11-18"
    sha256 = "59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029"
    ref1 = "https://shadowshell.io/fake-chrome-updater"
    ref2 = "https://bazaar.abuse.ch/sample/59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029/"

  strings:
        $0 = "ATwvXhg0JDYNWzQ6YVkYJyEoDVc7dD9CTSd0IkhOPDcjAw=="
        $1 = "Gh8="
        $2 = "OTshTlkhdGtO"
        $3 = "OTshTlkh"
        $4 = "GTshSl0ndCFCTHU/L0FUMDBoDWowJzJMSiE9KEoW"
        $5 = "GTshSl0ndDVZVyUkI0kW"

  condition:
    3 of them
}