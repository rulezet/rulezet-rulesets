rule AdwareELEXSampleCommon
{
	meta:
		Description  = "Adware.ELEX.vb"
		ThreatLevel  = "5"

	strings:

		$ = "\\Mozilla\\Firefox\\" ascii wide
		$ = "profiles.ini" ascii wide
		$ = "Profile0" ascii wide
		$ = "\\prefs.js" ascii wide
		$ = "\\Google\\Chrome\\User Data\\" ascii wide
		$ = "\\Secure Preferences" ascii wide
		$ = "Software\\Microsoft\\Internet Explorer\\Main" ascii wide
		$ = "Start Page" ascii wide
		$ = "chrome.exe" ascii wide
		$ = "iexplore.exe" ascii wide
		$ = "firefox.exe" ascii wide
		$ = "user_pref" ascii wide
		$ = "browser.startup.homepage" ascii wide
		$ = "startup_urls" ascii wide

	condition:
		all of them
}