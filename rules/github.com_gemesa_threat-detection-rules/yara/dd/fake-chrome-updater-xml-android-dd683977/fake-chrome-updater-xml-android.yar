rule fake_chrome_updater_xml_android {
  meta:
    description = "Fake Chrome updater main.xml (Android)"
    author = "Andras Gemes"
    date = "2025-11-18"
    sha256 = "59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029"
    ref1 = "https://shadowshell.io/fake-chrome-updater"
    ref2 = "https://bazaar.abuse.ch/sample/59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029/"

  strings:
    $0 = "Google Chrome Updater"
        $1 = /Your Chrome version is outdated! Chrome version: \d+\.\d+ \(\d+ years ago!\)/
    $2 = "Download and install update"

  condition:
    3 of them
}