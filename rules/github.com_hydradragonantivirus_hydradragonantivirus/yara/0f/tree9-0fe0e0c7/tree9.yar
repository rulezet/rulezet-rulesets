rule tree9 {
  strings:
    $s0    = "ZL20fixStringForCoreDataP11objc" fullword
    $s1    = "9allocatorIcEEEC1ERKS5" fullword
    $s2    = "willChangeStatusBarOrientation" fullword
    $s3    = "inactiveTitleBarStartColor" fullword
    $s4    = "initializeClassPair" fullword
    $s5    = "ZN5boost19thread" fullword
    $s6    = "updatedStatusTitle" fullword
    $s7    = "RequestFPGACount" fullword
    $s8    = "UHAWAVAUATSHxLMMIHHExHhHEhHpHEpHxHE" fullword
    $s9    = "AECreateAppleEvent" fullword
    $s10   = "dictionaryWithJSONString" fullword
    $s11   = "welcomeScreenIdentifier" fullword
    $s12   = "setStandardOutput" fullword
    $s13   = "ZBLocalizationContext" fullword
    $s14   = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s15   = "EqualizationPhase2" fullword
    $s16   = "DraggingViewNotificationIcon" fullword
    $s17   = "KGWindowsController" fullword
    $s18   = "CFStringMakeConstantString" fullword
    $s19   = "isAppStoreDistribution" fullword
    $s20   = "krStringWithUUID" fullword
    $s21   = "setSearchProvider" fullword
    $s22   = "URLRequestExtension" fullword
    $s23   = "SleepNotificationMBS" fullword
    $s24   = "getAuthorization" fullword
    $s25   = "kZBZeoAccountLoggedInNotification" fullword
    $s26   = "12CrtAllocatorELj0EE12PrettyPrefixENS" fullword
    $s27   = "140305162647Z0A1" fullword
    $s28   = "initWithNCController" fullword
    $s29   = "CSGetLocalIdentityAuthority" fullword
    $s30   = "threadSafeMainBundle" fullword
    $s31   = "ZBSystemInformation" fullword
    $s32   = "ApplicationServices" fullword
    $s33   = "introductionView" fullword
    $s34   = "CFBundleIdentifier" fullword
    $s35   = "191128154500Z0A1" fullword
    $s36   = "20191105000000Z0" fullword
    $s37   = "UHAWAVAUATSHxMLEUuAH" fullword
    $s38   = "kZBSizeStringKey" fullword
    $s39   = "sqhIJsyyeFaPcYe7" fullword
    $s40   = "handleHomeButtonSinglePressUp" fullword
    $s41   = "stringWithFormat" fullword
    $s42   = "ZN26DbMultipleRecnoDataBuilderC2ER3Dbt" fullword
    $s43   = "linenoiseEditInsert" fullword
    $s44   = "ZN9QListData7disposeEPNS" fullword
    $s45   = "getblocktemplate" fullword
    $s46   = "270201221215Z0y1" fullword
    $s48   = "certificateauthority0" fullword
    $s49   = "enumerationMutation" fullword
    $s50   = "NSAutoreleasePool" fullword
    $s51   = "NSAddressOfSymbol" fullword
    $s53   = "350209214036Z0b1" fullword
    $s54   = "ImageCaptureCore" fullword
    $s55   = "NetworkExtension" fullword
    $s56   = "NSNotificationCenter" fullword
    $s57   = "stringByAppendingPathComponent" fullword
    $s58   = "debugDescription" fullword
    $s59   = "retainAutoreleasedReturnValue" fullword
    $s60   = "kCFAllocatorDefault" fullword
    $s61   = "retainAutorelease" fullword
    $s62   = "libswiftCoreFoundation" fullword
    $s63   = "SystemConfiguration" fullword
    $s64   = "autoreleaseReturnValue" fullword
    $s65   = "CFConstantStringClassReference" fullword
    $s67   = "PrivateFrameworks" fullword
    $s68   = "MobileCoreServices" fullword
    $s69   = "iPhoneSimulator10" fullword
    $s70   = "DefaultRuneLocale" fullword
    $s71   = "ZTSN5boost9exceptionE" fullword
    $s74   = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s77   = "9allocatorIcEEEE" fullword
    $s78   = "libswiftCoreGraphics" fullword
    $s81   = "ServiceManagement" fullword
    $s98   = "UserNotifications" fullword
    $s100  = "libswiftDispatch" fullword
    $s117  = "deletedMethodError" fullword
    $s118  = "copyElephantBrain" fullword
    $s119  = "initWithCapacity" fullword
    $s120  = "abcdefghijklmnopqrstuvwxyz" fullword
    $s121  = "TZFE10FoundationSS36" fullword
    $s124  = "HMHMHMHMHMHMHMHMH" fullword
    $s125  = "IHEHEHEHEHEHEHEL" fullword
    $s127  = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s129  = "ddddddddddddddddddddddddddddddddsd" fullword
    $s132  = "removeObjectForKey" fullword
    $s133  = "certificationauthority" fullword
    $s134  = "HMHMHMHMHMHMHMHML" fullword
    $s135  = "HEHEHEHEHEHEHEHEHEHEHE" fullword
    $s138  = "DEDEDEDEDEDEDEDE9E" fullword
    $s139  = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s140  = "encodeURIComponent" fullword
    $s141  = "UHAWAVAUATSHHHuE" fullword
    $s145  = "retainAutoreleaseReturnValue" fullword
    $s146  = "localizedStringForKey" fullword
    $s148  = "adjustsLetterSpacingToFitWidth" fullword
    $s149  = "respondsToSelector" fullword
    $s150  = "scheduledTimerWithTimeInterval" fullword
    $s151  = "DisableThreadLibraryCalls" fullword
    $s153  = "NSConcreteGlobalBlock" fullword
    $s154  = "IOIteratorIsValid" fullword
    $s157  = "numberWithDouble" fullword
    $s160  = "fileExistsAtPath" fullword
    $s161  = "arrayWithObjects" fullword
    $s164  = "FromStringAndSize" fullword
    $s165  = "UHAWAVAUATSH8IIH" fullword
    $s167  = "NSStringFromClass" fullword
    $s175  = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s180  = "UHAWAVAUATSPIHIH" fullword
    $s181  = "lswiftObjectiveC" fullword
    $s182  = "dataUsingEncoding" fullword
    $s217  = "HEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEgqV" fullword
    $s218  = "traitsIcEEE3putEc" fullword
    $s225  = "UHAWAVAUATSPIIHt" fullword
    $s251  = "CFArrayGetValueAtIndex" fullword
    $s268  = "conformsToProtocol" fullword
    $s270  = "userInterfaceIdiom" fullword
    $s271  = "SecItemCopyMatching" fullword
    $s272  = "loadWeakRetained" fullword
    $s275  = "getExistentialTypeMetadata" fullword
    $s281  = "HEHEHEHEHEHEHEHEHEHEHEHEI" fullword
    $s284  = "ellipticcurvelist" fullword
    $s287  = "UHAWAVAUATSPAAII" fullword
    $s289  = "ZN9QListData11shared" fullword
    $s290  = "JSValueMakeBoolean" fullword
    $s291  = "certificateauthority" fullword
    $s293  = "UHAWAVAUATSH8IHH" fullword
    $s294  = "CFStringCreateWithCString" fullword
    $s296  = "category23default" fullword
    $s299  = "contentsOfDirectoryAtPath" fullword
    $s301  = "CFStringGetCString" fullword
    $s302  = "JSObjectSetProperty" fullword
    $s303  = "IOCreatePlugInInterfaceForService" fullword
    $s304  = "autoreleasePoolPop" fullword
    $s384  = "UIModalPresentationOverCurrentContext" fullword
    $s417  = "applicationShouldOpenUntitledFile" fullword
    $s418  = "countByEnumeratingWithState" fullword
    $s419  = "sharedApplication" fullword
    $s420  = "dictionaryWithContentsOfFile" fullword
    $s429  = "getInitializedObjCClass" fullword
    $s431  = "CFDictionaryCreateMutable" fullword
    $s434  = "completionHandler" fullword
    $s437  = "mediumspringgreen" fullword
    $s440  = "GenerateConnectionID" fullword
    $s445  = "UHAWAVAUATSH8HIH" fullword
    $s446  = "expectedContentLength" fullword
    $s449  = "ShCsSwSzfKpADKfADCNK" fullword
    $s457  = "numberWithUnsignedLong" fullword
    $s458  = "stringWithUTF8String" fullword
    $s461  = "0123456789abcdef" fullword
    $s464  = "9allocatorIcEEE6insertEmPKcm" fullword
    $s465  = "terminationStatus" fullword
    $s470  = "ecpointformatlist" fullword
    $s473  = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s476  = "getInstanceMethod" fullword
    $s477  = "createFileAtPath" fullword
    $s480  = "glFramebufferTextureLayer" fullword
    $s481  = "traitsIcEEE9showmanycEv" fullword
    $s484  = "UHAWAVAUATSH8IIHH" fullword
    $s485  = "ZTVN14RegisterResult16RegistrationDataE" fullword
    $s488  = "StringCharCodeAt" fullword
    $s489  = "NSFetchedPropertyDescription" fullword
    $s494  = "CFURLGetFileSystemRepresentation" fullword
    $s497  = "getTupleTypeMetadata2" fullword
    $s498  = "resignFirstResponder" fullword
    $s499  = "getImplementation" fullword
    $s526  = "UHAWAVAUATSPAIIB" fullword
    $s600  = "constants10error" fullword
    $s601  = "ZTSN5boost18thread" fullword
    $s604  = "N5boost9exceptionE" fullword
    $s619  = "HEHEHEHEHEHEHEHE" fullword
    $s620  = "GetDiskFreeSpace" fullword
    $s624  = "15mutex6unlockEv" fullword
    $s625  = "CFBundleGetVersionNumber" fullword
    $s660  = "copyClassNamesForImage" fullword
    $s665  = "UIKeyboardAnimationCurveUserInfoKey" fullword
    $s689  = "responseSerializer" fullword
    $s694  = "UIGestureRecognizer" fullword
    $s696  = "k7kBkQkpkkkkkkkkkkflmllllll" fullword
    $s701  = "ddddduhhhhhhhhhh" fullword
    $s720  = "systemFontOfSize" fullword
    $s721  = "CGPathCreateMutable" fullword
    $s723  = "shouldHighlightRowAtIndexPath" fullword
    $s724  = "imageWithCGImage" fullword
    $s725  = "NSURLSessionDataTask" fullword
    $s730  = "ponponqqtsrtsruuxwvwvyy" fullword
    $s731  = "Z83Z8CZ8SZ8cZ8sZ82" fullword
    $s751  = "replaceObjectAtIndex" fullword
    $s755  = "lengthOfBytesUsingEncoding" fullword
    $s761  = "convertBoolToObjCBoolyAA0eF0VSbF" fullword
    $s762  = "sSS10FoundationE4data8encodingSSSgAA4DataVh" fullword
    $s767  = "launchJavaApplication" fullword
    $s768  = "UHAWAVAUATSH8LMHMHUHuHH" fullword
    $s769  = "AssemblyProductAttribute" fullword
    $s770  = "s8Dispatch0A4TimeVMa" fullword
    $s771  = "TpEQULved3Ly7GqqbjLfo6hqMSo" fullword
    $s772  = "addUndeleterFilesRecovered" fullword
    $s773  = "defaultSessionConfiguration" fullword
    $s774  = "applicationDidUnhide" fullword
    $s775  = "UHAWAVAUATSH8IHuIH" fullword
    $s776  = "UHAWAVAUATSPDEAI" fullword
    $s779  = "UHAWAVAUATSPIIID" fullword
    $s782  = "140213191008Z0A1" fullword
    $s783  = "140129192647Z0A1" fullword
    $s785  = "MacKeeperPrivilegedHelper" fullword
    $s787  = "CFNumberGetValue" fullword
    $s799  = "CFReadStreamCreateWithFile" fullword
    $s806  = "AuthorizationFree" fullword
    $s810  = "initWithContentsOfURL" fullword
    $s813  = "200219223002Z0B1" fullword
    $s815  = "e4zPO0A75QibEoIM1dS3ccGV3ag" fullword
    $s845  = "191127221001Z0A1" fullword
    $s861  = "CFBundleCopyResourceURL" fullword
    $s862  = "crossCertificatePair" fullword
    $s882  = "UHAWAVAUATSPIHIIH" fullword
    $s961  = "UHAWAVAUATSPIIIu0Ht" fullword
    $s964  = "toefG0s0fG0VSgyFTW" fullword
    $s972  = "NSDistributedNotificationCenter" fullword
    $s986  = "JavaApplicationStub" fullword
    $s997  = "ZBNTFSVolumeScanner" fullword
    $s1003 = "IOServiceGetMatchingServices" fullword
    $s1010 = "dataWithContentsOfFile" fullword
    $s1011 = "didRegisterForRemoteNotificationsWithDeviceToken" fullword
    $s1013 = "delegateHandlesKey" fullword
    $s1020 = "ZN2cv10AutoBufferIhLm4104EE8allocateEm" fullword
    $s1025 = "NSRunningApplication" fullword
    $s1028 = "stringWithString" fullword
    $s1060 = "ZN7QLayout18setContentsMarginsEiiii" fullword
    $s1061 = "ZN16QLoggingCategoryD1Ev" fullword
    $s1066 = "4sxpkxaSWLSlAJiaKPaIibCAcmY" fullword
    $s1076 = "URLSessionDidFinishEventsForBackgroundURLSession" fullword
    $s1078 = "getGenericMetadata1" fullword
    $s1088 = "ContiguousaB0Vy7ElementQzGz" fullword
    $s1101 = "CreateDeviceAsyncEventSource" fullword
    $s1108 = "ZBNetworkReachability" fullword
    $s1110 = "isAccessibilityElement" fullword
    $s1112 = "CFBundleExecutable" fullword
    $s1113 = "NSPropertyListSerialization" fullword
    $s1114 = "numberWithUnsignedInt" fullword
    $s1115 = "webScriptNameForSelector" fullword
    $s1118 = "bundleIdentifier" fullword
    $s1127 = "IORegistryEntryCreateCFProperty" fullword
    $s1133 = "210412223435Z0V1" fullword
    $s1134 = "CGContextStrokePath" fullword
    $s1145 = "NSStringPboardType" fullword
    $s1176 = "caseInsensitiveCompare" fullword
    $s1185 = "systemVersionString" fullword
    $s1186 = "CGContextRelease" fullword
    $s1198 = "applicationWillUnhide" fullword
    $s1224 = "valueForProperty" fullword
    $s1225 = "LSHandlerURLScheme" fullword
    $s1229 = "setHTTPShouldHandleCookies" fullword
    $s1232 = "localizedCaseInsensitiveCompare" fullword
    $s1235 = "mouseLocationOutsideOfEventStream" fullword
    $s1236 = "initWithIdentifier" fullword
    $s1252 = "kSecMatchLimitAll" fullword
    $s1255 = "readDataOfLength" fullword
    $s1256 = "CFBundleInfoDictionaryVersion" fullword
    $s1263 = "componentsSeparatedByString" fullword
    $s1275 = "setCanChooseDirectories" fullword
    $s1306 = "numberWithUnsignedInteger" fullword
    $s1308 = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s1317 = "updateCheckInterval" fullword
    $s1318 = "isJavaInstalledInternal" fullword
    $s1320 = "viewForTableColumn" fullword
    $s1321 = "componentsSeparatedByCharactersInSet" fullword
    $s1322 = "calculateRegexesInfoIfNeededWithShouldCancelBlock" fullword
    $s1323 = "setStandardInput" fullword
    $s1326 = "NSFilenamesPboardType" fullword
    $s1335 = "substringToIndex" fullword
    $s1340 = "replacementString" fullword
    $s1343 = "isItemExpandable" fullword
    $s1346 = "NSMutableURLRequest" fullword
    $s1362 = "connectionDidFinishLoading" fullword
    $s1366 = "timeIntervalSinceDate" fullword
    $s1389 = "didFailToRegisterForRemoteNotificationsWithError" fullword
    $s1402 = "fileHandleForReading" fullword
    $s1409 = "baseIN5boost9sub" fullword
    $s1414 = "whatIsPluginDescription" fullword
    $s1416 = "NSDraggingSession" fullword
    $s1418 = "getMethodDescription" fullword
    $s1420 = "kZBVTIFileSizeByteNumberKey" fullword
    $s1422 = "kZBIdentifierKey" fullword
    $s1424 = "UHAWAVAUATSPIIIMthMtcL" fullword
    $s1425 = "NSDistantObjectRequest" fullword
    $s1430 = "withIntermediateDirectories" fullword
    $s1434 = "backingScaleFactor" fullword
    $s1437 = "kCFCoreFoundationVersionNumber" fullword
    $s1462 = "applicationDockMenu" fullword
    $s1465 = "shouldDragDocumentWithEvent" fullword
    $s1470 = "RGp0SARARARARARA" fullword
    $s1495 = "IOPlatformExpertDevice" fullword
    $s1519 = "cancelButtonTitle" fullword
    $s1540 = "stackFrameWithSymbol" fullword
    $s1553 = "NSAssertionHandler" fullword
    $s1557 = "gestureRecognizer" fullword
    $s1559 = "fastIndexForKnownKey" fullword
    $s1562 = "NSURLSessionDataDelegate" fullword
    $s1564 = "willDismissWithButtonIndex" fullword
    $s1572 = "willEncodeRestorableStateWithCoder" fullword
    $s1575 = "enumerateObjectsUsingBlock" fullword
    $s1582 = "setExpiryDarkModeLabel" fullword
    $s1584 = "bridgeToObjectiveCSo5NSURLCyF" fullword
    $s1592 = "shouldChangeCharactersInRange" fullword
    $s1597 = "NSOperationQueue" fullword
    $s1604 = "N4laya11JSCFunctionIPFvllEEE" fullword
    $s1605 = "dataTaskWithRequest" fullword
    $s1606 = "reachabilityWithHostName" fullword
    $s1608 = "appNeedsOnboarding" fullword
    $s1609 = "JKDictionaryClass" fullword
    $s1620 = "ZTVN5boost4asio5error6detail12ssl" fullword
    $s1621 = "N5boost6detail11thread" fullword
    $s1625 = "N5boost9gregorian15bad" fullword
    $s1627 = "CFBundleShortVersionString" fullword
    $s1659 = "constructInstance" fullword
    $s1660 = "34CachingTransactionSignatureChecker" fullword
    $s1661 = "IOServiceTerminate" fullword
    $s1662 = "ZTIN8CryptoPP12ClonableImplINS" fullword
    $s1664 = "ZTI15CCoinsViewCache" fullword
    $s1672 = "EEEEEEEEE7disposeEv" fullword
    $s1673 = "objectForKeyedSubscript" fullword
    $s1680 = "createDirectoryAtURL" fullword
    $s1693 = "operatingSystemVersionString" fullword
    $s1702 = "fetchCompletionHandler" fullword
    $s1704 = "connectionRequired" fullword
    $s1705 = "UIViewController" fullword
    $s1726 = "SecStaticCodeCheckValidityWithErrors" fullword
    $s1735 = "E6targetERKSt9type" fullword
    $s1742 = "configureFromArgEPKc" fullword
    $s1750 = "SSTTableFileName" fullword
    $s1753 = "ZN9QListData6appendERKS" fullword
    $s1761 = "timerWithTimeInterval" fullword
    $s1764 = "arrayWithCapacity" fullword
    $s1766 = "fkzienviptjqzaavumcectmwezot" fullword
    $s1770 = "ConnectionProvider" fullword
    $s1771 = "ZBUSystemInformation" fullword
    $s1774 = "kMKAlertNotificationServiceName" fullword
    $s1775 = "setInstanceVariableP11objc" fullword
    $s1776 = "fileManagerByPreservingAuthorizationRights" fullword
    $s1777 = "ZL22copySwiftV1MangledNamePKcb" fullword
    $s1783 = "characterIsMember" fullword
    $s1789 = "runningApplications" fullword
    $s1807 = "appropriateForDirectoryURL" fullword
    $s1808 = "IntermediateBuildFilesPath" fullword
    $s1810 = "autoreleasepoolPK11mach" fullword
    $s1813 = "continueUserActivity" fullword
    $s1818 = "initWithSuiteName" fullword
    $s1820 = "redirectResponse" fullword
    $s1821 = "clientDidConnectWithConnection" fullword
    $s1826 = "stringCompareWithSmolCheck" fullword
    $s1841 = "SCNetworkReachabilityUnscheduleFromRunLoop" fullword
    $s1864 = "dataWithJSONObject" fullword
    $s1867 = "CFStreamCreatePairWithSocket" fullword
    $s1870 = "registerClassPair" fullword
    $s1876 = "RARARARARARARARARARAZAp" fullword
    $s1888 = "s8webtools15SafariInstallerC15wtDaemonRunning33" fullword
    $s1889 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1899 = "ZL12cxxConstructP11objc" fullword
    $s1901 = "NSLayoutConstraint" fullword
    $s1925 = "SecStaticCodeCreateWithPath" fullword
    $s1934 = "CGRectContainsPoint" fullword
    $s1936 = "didRegisterUserNotificationSettings" fullword
    $s1938 = "CGContextFillPath" fullword
    $s1941 = "NSSharingServicePicker" fullword
    $s1942 = "implementationWithBlock" fullword
    $s1943 = "collectingEnabled" fullword
    $s1944 = "kSecAttrAuthenticationTypeMSN" fullword
    $s1946 = "didPresentAlertView" fullword
    $s1948 = "NSUndoManagerProxy" fullword
    $s1949 = "applicationWillHide" fullword
    $s1950 = "DEISHUISHUISHxMLH" fullword
    $s1979 = "replaceCharactersInRange" fullword
    $s1980 = "showNotification" fullword
    $s1988 = "initWithFabricAggregator" fullword

  condition:
    ((#s0 <= 0.5)
      and ((#s1 <= 3.0)
        and ((#s2 <= 0.5)
          and ((#s3 <= 1.0)
            and ((#s4 <= 0.5)
              and ((#s5 <= 2.5)
                and ((#s6 <= 0.5)
                  and ((#s7 <= 0.5)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 2.5)
                        and ((#s10 <= 1.5)
                          and ((#s11 <= 0.5)
                            and ((#s12 <= 0.5)
                              and ((#s13 <= 0.5)
                                and ((#s14 <= 0.5)
                                  and ((#s15 <= 0.5)
                                    and ((#s16 <= 0.5)
                                      and ((#s17 <= 0.5)
                                        and ((#s18 <= 1.5)
                                          and ((#s19 <= 0.5)
                                            and ((#s20 <= 0.5)
                                              and ((#s21 <= 0.5)
                                                and ((#s22 <= 4.0)
                                                  and ((#s23 <= 1.0)
                                                    and ((#s24 <= 1.0)
                                                      and ((#s25 <= 0.5)
                                                        and ((#s26 <= 0.5)
                                                          and ((#s27 <= 0.5)
                                                            and ((#s28 <= 0.5)
                                                              and ((#s29 <= 1.0)
                                                                and ((#s30 <= 0.5)
                                                                  and ((#s31 <= 1.0)
                                                                    and ((#s32 <= 1.5)
                                                                      and ((#s33 <= 0.5)
                                                                        and ((#s34 <= 0.5)
                                                                          and ((#s35 <= 0.5)
                                                                            and ((#s36 <= 0.5)
                                                                              and ((#s37 <= 0.5)
                                                                                and ((#s38 <= 1.0)
                                                                                  and ((#s39 <= 0.5)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((#s41 <= 0.5)
                                                                                        and ((#s42 <= 0.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((#s44 <= 0.5)
                                                                                              and ((#s45 <= 0.5)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((filesize <= 50006.0)
                                                                                                    and ((#s48 <= 0.5)
                                                                                                      and ((#s49 <= 1.5)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 0.5)
                                                                                                            and ((filesize <= 11072.0)
                                                                                                              and ((#s53 <= 0.5)
                                                                                                                and ((#s54 <= 1.0)
                                                                                                                  and ((#s55 <= 0.5)
                                                                                                                    and ((#s56 <= 4.5)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 0.5)
                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                              and ((#s61 <= 0.5)
                                                                                                                                and ((#s62 <= 0.5)
                                                                                                                                  and ((#s63 <= 1.5)
                                                                                                                                    and ((#s64 <= 0.5)
                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                        and ((#s63 <= 0.5)
                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                            and ((#s68 <= 1.0)
                                                                                                                                              and ((#s69 <= 1.5)
                                                                                                                                                and ((#s70 <= 0.5)
                                                                                                                                                  and ((#s71 <= 0.5)
                                                                                                                                                    and ((filesize > 5176.0)
                                                                                                                                                      and ((#s74 <= 0.5)
                                                                                                                                                        and ((filesize <= 5194.0)
                                                                                                                                                          or (filesize > 5194.0)
                                                                                                                                                          and ((#s77 <= 3.0)
                                                                                                                                                            and ((#s78 <= 0.5)
                                                                                                                                                              and ((filesize > 8946.0)
                                                                                                                                                                and ((#s81 <= 3.0)
                                                                                                                                                                  and ((filesize <= 8970.0)
                                                                                                                                                                  )))))))))))))))) or (#s63 > 1.5)
                                                                                                                                    and ((#s32 <= 0.5)
                                                                                                                                      and ((#s98 > 1.0)
                                                                                                                                        and ((#s100 <= 0.5)
                                                                                                                                          and ((#s68 > 1.0)
                                                                                                                                          ))))))))))))))) or (filesize > 11072.0)
                                                                                                              and ((#s68 <= 1.5)
                                                                                                                and ((#s117 <= 0.5)
                                                                                                                  and ((#s118 <= 1.5)
                                                                                                                    and ((#s119 <= 0.5)
                                                                                                                      and ((#s120 <= 0.5)
                                                                                                                        and ((#s121 <= 0.5)
                                                                                                                          and ((#s70 <= 0.5)
                                                                                                                            and ((#s67 <= 1.5)
                                                                                                                              and ((#s124 <= 0.5)
                                                                                                                                and ((#s125 <= 0.5)
                                                                                                                                  and ((#s65 <= 0.5)
                                                                                                                                    and ((#s127 <= 0.5)
                                                                                                                                      and ((#s1 <= 0.5)
                                                                                                                                        and ((#s129 <= 0.5)
                                                                                                                                          and ((#s60 <= 0.5)
                                                                                                                                            and ((#s49 <= 0.5)
                                                                                                                                              and ((#s132 <= 0.5)
                                                                                                                                                and ((#s133 <= 0.5)
                                                                                                                                                  and ((#s134 <= 0.5)
                                                                                                                                                    and ((#s135 <= 0.5)
                                                                                                                                                      and ((filesize <= 26118.0)
                                                                                                                                                        and ((#s78 <= 0.5)
                                                                                                                                                          and ((#s138 <= 0.5)
                                                                                                                                                            and ((#s139 <= 1.0)
                                                                                                                                                              and ((#s140 <= 0.5)
                                                                                                                                                                and ((#s141 <= 0.5)
                                                                                                                                                                  and ((#s53 <= 0.5)
                                                                                                                                                                    and ((#s56 <= 0.5)
                                                                                                                                                                      and ((#s63 <= 0.5)
                                                                                                                                                                        and ((#s145 <= 0.5)
                                                                                                                                                                          and ((#s146 <= 0.5)
                                                                                                                                                                            and ((#s54 <= 1.0)
                                                                                                                                                                              and ((#s148 <= 0.5)
                                                                                                                                                                                and ((#s149 <= 0.5)
                                                                                                                                                                                  and ((#s150 <= 2.5)
                                                                                                                                                                                    and ((#s151 <= 1.0)
                                                                                                                                                                                      and ((#s71 <= 0.5)
                                                                                                                                                                                        and ((#s153 <= 0.5)
                                                                                                                                                                                          and ((#s154 <= 1.0)
                                                                                                                                                                                            and ((#s61 <= 0.5)
                                                                                                                                                                                              and ((#s69 <= 1.0)
                                                                                                                                                                                                and ((#s157 <= 0.5)
                                                                                                                                                                                                  and ((#s81 <= 1.0)
                                                                                                                                                                                                    and ((filesize <= 25034.0)
                                                                                                                                                                                                      and ((#s160 <= 0.5)
                                                                                                                                                                                                        and ((#s161 <= 0.5)
                                                                                                                                                                                                          and ((#s77 <= 0.5)
                                                                                                                                                                                                            and ((#s59 <= 0.5)
                                                                                                                                                                                                              and ((#s164 <= 0.5)
                                                                                                                                                                                                                and ((#s165 <= 0.5)
                                                                                                                                                                                                                  and ((filesize <= 16444.0)
                                                                                                                                                                                                                    and ((#s167 <= 0.5)
                                                                                                                                                                                                                      and ((filesize <= 12546.0)
                                                                                                                                                                                                                        and ((filesize > 12530.0)
                                                                                                                                                                                                                        ))) or (filesize > 16444.0)
                                                                                                                                                                                                                    and ((#s74 <= 1.0)
                                                                                                                                                                                                                      and ((#s175 <= 0.5)
                                                                                                                                                                                                                        and ((#s167 <= 0.5)
                                                                                                                                                                                                                          and ((filesize <= 16478.0)
                                                                                                                                                                                                                            or (filesize > 16478.0)
                                                                                                                                                                                                                            and ((#s58 <= 0.5)
                                                                                                                                                                                                                              and ((#s180 <= 0.5)
                                                                                                                                                                                                                                and ((#s181 <= 0.5)
                                                                                                                                                                                                                                  and ((#s182 <= 0.5)
                                                                                                                                                                                                                                    and ((filesize <= 20788.0)
                                                                                                                                                                                                                                      and ((filesize > 18982.0)
                                                                                                                                                                                                                                        and ((filesize <= 19022.0)
                                                                                                                                                                                                                                        )) or (filesize > 20788.0)
                                                                                                                                                                                                                                      and ((filesize <= 20802.0)
                                                                                                                                                                                                                                        or (filesize > 20802.0)
                                                                                                                                                                                                                                        and ((filesize <= 21653.5)
                                                                                                                                                                                                                                          and ((filesize <= 21624.0)
                                                                                                                                                                                                                                            and ((filesize > 21020.0)
                                                                                                                                                                                                                                              and ((filesize <= 21100.0)
                                                                                                                                                                                                                                                or (filesize > 21100.0)
                                                                                                                                                                                                                                                and ((filesize <= 21396.0)
                                                                                                                                                                                                                                                  and ((filesize > 21240.0)
                                                                                                                                                                                                                                                  )))) or (filesize > 21624.0)
                                                                                                                                                                                                                                          )))))))))) or (#s175 > 0.5)
                                                                                                                                                                                                                      ))))))))) or (filesize > 25034.0)
                                                                                                                                                                                                      and ((#s217 <= 0.5)
                                                                                                                                                                                                        and ((#s218 <= 1.0)
                                                                                                                                                                                                          and ((filesize <= 25284.0)
                                                                                                                                                                                                            and ((filesize <= 25140.0)
                                                                                                                                                                                                              and ((filesize <= 25112.0)
                                                                                                                                                                                                              ) or (filesize > 25140.0)
                                                                                                                                                                                                            ) or (filesize > 25284.0)
                                                                                                                                                                                                            and ((#s225 <= 0.5)
                                                                                                                                                                                                              and ((filesize > 26048.0)
                                                                                                                                                                                                              )))) or (#s217 > 0.5)
                                                                                                                                                                                                      )))))))))))))))) or (#s63 > 0.5)
                                                                                                                                                                        and ((#s64 <= 0.5)
                                                                                                                                                                          and ((#s98 <= 0.5)
                                                                                                                                                                            and ((#s63 > 1.5)
                                                                                                                                                                              and ((#s81 <= 1.0)
                                                                                                                                                                                and ((#s251 <= 0.5)
                                                                                                                                                                                  and ((filesize > 17296.0)
                                                                                                                                                                                    and ((filesize <= 19830.0)
                                                                                                                                                                                    )))))))))) or (#s141 > 0.5)
                                                                                                                                                                ))) or (#s138 > 0.5)
                                                                                                                                                          )) or (filesize > 26118.0)
                                                                                                                                                        and ((#s268 <= 0.5)
                                                                                                                                                          and ((#s167 <= 0.5)
                                                                                                                                                            and ((#s270 <= 0.5)
                                                                                                                                                              and ((#s271 <= 1.0)
                                                                                                                                                                and ((#s272 <= 0.5)
                                                                                                                                                                  and ((#s63 <= 1.5)
                                                                                                                                                                    and ((#s69 <= 1.0)
                                                                                                                                                                      and ((#s275 <= 0.5)
                                                                                                                                                                        and ((#s151 <= 1.0)
                                                                                                                                                                          and ((#s100 <= 0.5)
                                                                                                                                                                            and ((#s81 <= 1.0)
                                                                                                                                                                              and ((#s59 <= 0.5)
                                                                                                                                                                                and ((#s175 <= 0.5)
                                                                                                                                                                                  and ((#s281 <= 0.5)
                                                                                                                                                                                    and ((#s164 <= 0.5)
                                                                                                                                                                                      and ((#s67 <= 0.5)
                                                                                                                                                                                        and ((#s284 <= 1.0)
                                                                                                                                                                                          and ((#s139 <= 1.0)
                                                                                                                                                                                            and ((#s9 <= 0.5)
                                                                                                                                                                                              and ((#s287 <= 0.5)
                                                                                                                                                                                                and ((#s181 <= 0.5)
                                                                                                                                                                                                  and ((#s289 <= 0.5)
                                                                                                                                                                                                    and ((#s290 <= 1.5)
                                                                                                                                                                                                      and ((#s291 <= 0.5)
                                                                                                                                                                                                        and ((#s180 <= 0.5)
                                                                                                                                                                                                          and ((#s293 <= 0.5)
                                                                                                                                                                                                            and ((#s294 <= 0.5)
                                                                                                                                                                                                              and ((#s74 <= 1.0)
                                                                                                                                                                                                                and ((#s296 <= 3.0)
                                                                                                                                                                                                                  and ((#s71 <= 0.5)
                                                                                                                                                                                                                    and ((#s32 <= 0.5)
                                                                                                                                                                                                                      and ((#s299 <= 0.5)
                                                                                                                                                                                                                        and ((#s138 <= 0.5)
                                                                                                                                                                                                                          and ((#s301 <= 0.5)
                                                                                                                                                                                                                            and ((#s302 <= 1.0)
                                                                                                                                                                                                                              and ((#s303 <= 2.0)
                                                                                                                                                                                                                                and ((#s304 <= 1.5)
                                                                                                                                                                                                                                  and ((filesize > 32996.0)
                                                                                                                                                                                                                                    and ((#s53 <= 0.5)
                                                                                                                                                                                                                                      and ((filesize > 33116.0)
                                                                                                                                                                                                                                        and ((filesize <= 38385.0)
                                                                                                                                                                                                                                          and ((filesize > 38276.0)
                                                                                                                                                                                                                                          ))))))))) or (#s138 > 0.5)
                                                                                                                                                                                                                        ))))))))))))))))))) or (#s281 > 0.5)
                                                                                                                                                                                  ) or (#s175 > 0.5)
                                                                                                                                                                                ))))))) or (#s63 > 1.5)
                                                                                                                                                                    and ((filesize <= 37144.0)
                                                                                                                                                                      and ((filesize > 33692.0)
                                                                                                                                                                      ))))))))) or (#s135 > 0.5)
                                                                                                                                                    ) or (#s134 > 0.5)
                                                                                                                                                  ))))) or (#s129 > 0.5)
                                                                                                                                        )) or (#s127 > 0.5)
                                                                                                                                      and ((filesize <= 22066.0)
                                                                                                                                      ))) or (#s125 > 0.5)
                                                                                                                                ) or (#s124 > 0.5)
                                                                                                                              )))) or (#s120 > 0.5)
                                                                                                                        and ((#s70 <= 1.0)
                                                                                                                          and ((#s120 <= 1.5)
                                                                                                                            and ((#s74 > 1.0)
                                                                                                                            ))))) or (#s118 > 1.5)
                                                                                                                  )) or (#s68 > 1.5)
                                                                                                                and ((#s384 <= 0.5)
                                                                                                                  and ((#s65 <= 0.5)
                                                                                                                    and ((#s68 <= 2.5)
                                                                                                                      and ((#s55 <= 1.0)
                                                                                                                        and ((#s78 <= 0.5)
                                                                                                                          and ((#s67 <= 1.0)
                                                                                                                            and ((filesize <= 11498.0)
                                                                                                                              or (filesize > 11498.0)
                                                                                                                              and ((filesize <= 14060.0)
                                                                                                                                and ((#s98 > 1.0)
                                                                                                                                ))))) or (#s55 > 1.0)
                                                                                                                        and ((#s98 > 1.0)
                                                                                                                          and ((filesize <= 14024.0)
                                                                                                                            and ((filesize <= 12038.0)
                                                                                                                            ) or (filesize > 14024.0)
                                                                                                                            and ((filesize <= 16072.0)
                                                                                                                            ))))))))))) or (#s49 > 1.5)
                                                                                                        and ((#s299 <= 0.5)
                                                                                                          and ((#s153 <= 1.0)
                                                                                                            and ((#s417 <= 0.5)
                                                                                                              and ((#s418 <= 1.5)
                                                                                                                and ((#s419 <= 0.5)
                                                                                                                  and ((#s420 > 0.5)
                                                                                                                  )))))))) or (filesize > 50006.0)
                                                                                                    and ((#s429 <= 0.5)
                                                                                                      and ((#s48 <= 0.5)
                                                                                                        and ((#s431 <= 0.5)
                                                                                                          and ((#s153 <= 0.5)
                                                                                                            and ((#s149 <= 0.5)
                                                                                                              and ((#s434 <= 0.5)
                                                                                                                and ((#s98 <= 1.5)
                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                    and ((#s437 <= 0.5)
                                                                                                                      and ((#s127 <= 0.5)
                                                                                                                        and ((#s53 <= 0.5)
                                                                                                                          and ((#s440 <= 1.0)
                                                                                                                            and ((#s49 <= 0.5)
                                                                                                                              and ((#s59 <= 0.5)
                                                                                                                                and ((#s77 <= 0.5)
                                                                                                                                  and ((#s70 <= 0.5)
                                                                                                                                    and ((#s445 <= 0.5)
                                                                                                                                      and ((#s446 <= 0.5)
                                                                                                                                        and ((filesize <= 50240.0)
                                                                                                                                          and ((filesize <= 50114.0)
                                                                                                                                            and ((#s449 <= 0.5)
                                                                                                                                              and ((filesize <= 50062.0)
                                                                                                                                              ) or (#s449 > 0.5)
                                                                                                                                            ) or (filesize > 50114.0)
                                                                                                                                          ) or (filesize > 50240.0)
                                                                                                                                          and ((#s287 <= 0.5)
                                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                                              and ((#s457 <= 1.0)
                                                                                                                                                and ((#s458 <= 0.5)
                                                                                                                                                  and ((#s164 <= 0.5)
                                                                                                                                                    and ((#s65 <= 0.5)
                                                                                                                                                      and ((#s461 <= 0.5)
                                                                                                                                                        and ((#s293 <= 0.5)
                                                                                                                                                          and ((#s56 <= 0.5)
                                                                                                                                                            and ((#s464 <= 0.5)
                                                                                                                                                              and ((#s465 <= 0.5)
                                                                                                                                                                and ((#s139 <= 1.0)
                                                                                                                                                                  and ((#s151 <= 0.5)
                                                                                                                                                                    and ((#s51 <= 0.5)
                                                                                                                                                                      and ((#s18 <= 0.5)
                                                                                                                                                                        and ((#s470 <= 1.0)
                                                                                                                                                                          and ((#s124 <= 0.5)
                                                                                                                                                                            and ((#s69 <= 0.5)
                                                                                                                                                                              and ((#s473 <= 1.0)
                                                                                                                                                                                and ((#s67 <= 1.0)
                                                                                                                                                                                  and ((#s301 <= 0.5)
                                                                                                                                                                                    and ((#s476 <= 0.5)
                                                                                                                                                                                      and ((#s477 <= 0.5)
                                                                                                                                                                                        and ((#s289 <= 0.5)
                                                                                                                                                                                          and ((#s120 <= 0.5)
                                                                                                                                                                                            and ((#s480 <= 0.5)
                                                                                                                                                                                              and ((#s481 <= 0.5)
                                                                                                                                                                                                and ((#s154 <= 0.5)
                                                                                                                                                                                                  and ((#s58 <= 0.5)
                                                                                                                                                                                                    and ((#s484 <= 0.5)
                                                                                                                                                                                                      and ((#s485 <= 0.5)
                                                                                                                                                                                                        and ((#s50 <= 1.5)
                                                                                                                                                                                                          and ((#s71 <= 1.5)
                                                                                                                                                                                                            and ((#s488 <= 0.5)
                                                                                                                                                                                                              and ((#s489 <= 1.0)
                                                                                                                                                                                                                and ((filesize <= 169899.0)
                                                                                                                                                                                                                  and ((#s62 <= 0.5)
                                                                                                                                                                                                                    and ((#s78 <= 0.5)
                                                                                                                                                                                                                      and ((#s180 <= 0.5)
                                                                                                                                                                                                                        and ((#s494 <= 0.5)
                                                                                                                                                                                                                          and ((filesize <= 79752.0)
                                                                                                                                                                                                                            and ((#s165 <= 1.5)
                                                                                                                                                                                                                              and ((#s497 <= 0.5)
                                                                                                                                                                                                                                and ((#s498 <= 0.5)
                                                                                                                                                                                                                                  and ((#s499 <= 0.5)
                                                                                                                                                                                                                                    and ((#s74 <= 1.0)
                                                                                                                                                                                                                                      and ((filesize <= 79716.0)
                                                                                                                                                                                                                                        and ((#s218 <= 1.0)
                                                                                                                                                                                                                                          and ((filesize > 70920.0)
                                                                                                                                                                                                                                            and ((filesize <= 71180.0)
                                                                                                                                                                                                                                              or (filesize > 71180.0)
                                                                                                                                                                                                                                              and ((filesize <= 71394.0)
                                                                                                                                                                                                                                                and ((filesize > 71222.0)
                                                                                                                                                                                                                                                ))))) or (filesize > 79716.0)
                                                                                                                                                                                                                                      ))))))))))) or (filesize > 169899.0)
                                                                                                                                                                                                                  and ((#s304 <= 0.5)
                                                                                                                                                                                                                    and ((#s9 <= 0.5)
                                                                                                                                                                                                                      and ((#s526 <= 0.5)
                                                                                                                                                                                                                        and ((filesize <= 173868.0)
                                                                                                                                                                                                                          and ((filesize <= 173168.0)
                                                                                                                                                                                                                            and ((filesize <= 170620.0)
                                                                                                                                                                                                                            ) or (filesize > 173168.0)
                                                                                                                                                                                                                          ) or (filesize > 173868.0)
                                                                                                                                                                                                                          and ((#s180 <= 0.5)
                                                                                                                                                                                                                            and ((#s165 <= 0.5)
                                                                                                                                                                                                                              and ((#s74 <= 1.0)
                                                                                                                                                                                                                                and ((filesize > 457316.0)
                                                                                                                                                                                                                                  and ((filesize <= 462014.0)
                                                                                                                                                                                                                                    or (filesize > 462014.0)
                                                                                                                                                                                                                                    and ((filesize <= 624454.0)
                                                                                                                                                                                                                                      and ((filesize <= 615352.0)
                                                                                                                                                                                                                                        and ((filesize <= 467548.0)
                                                                                                                                                                                                                                          and ((filesize > 465502.0)
                                                                                                                                                                                                                                          )) or (filesize > 615352.0)
                                                                                                                                                                                                                                      ) or (filesize > 624454.0)
                                                                                                                                                                                                                                      and ((filesize > 1551558.5)
                                                                                                                                                                                                                                        and ((filesize <= 1923125.5)
                                                                                                                                                                                                                                        ))))))) or (#s180 > 0.5)
                                                                                                                                                                                                                            and ((filesize > 2236289.0)
                                                                                                                                                                                                                              and ((filesize <= 15940403.0)
                                                                                                                                                                                                                              )))))))))))))))))))))))))))))))))))))))))))))) or (#s70 > 0.5)
                                                                                                                                    and ((#s600 <= 1.5)
                                                                                                                                      and ((#s601 <= 1.0)
                                                                                                                                        and ((#s70 <= 1.5)
                                                                                                                                          and ((#s301 <= 0.5)
                                                                                                                                            and ((#s604 <= 0.5)
                                                                                                                                              and ((#s140 <= 0.5)
                                                                                                                                                and ((#s51 <= 0.5)
                                                                                                                                                  and ((filesize > 461981.5)
                                                                                                                                                    and ((#s120 > 1.0)
                                                                                                                                                      and ((#s461 <= 0.5)
                                                                                                                                                      ))))))) or (#s70 > 1.5)
                                                                                                                                          and ((#s65 <= 1.0)
                                                                                                                                            and ((#s619 <= 0.5)
                                                                                                                                              and ((#s620 <= 1.0)
                                                                                                                                                and ((#s70 <= 3.0)
                                                                                                                                                  and ((#s461 <= 0.5)
                                                                                                                                                    and ((#s180 <= 0.5)
                                                                                                                                                      and ((#s624 <= 1.0)
                                                                                                                                                        and ((#s625 <= 1.0)
                                                                                                                                                          and ((#s481 <= 1.0)
                                                                                                                                                            and ((#s480 <= 1.0)
                                                                                                                                                              and ((#s120 <= 0.5)
                                                                                                                                                                and ((#s140 <= 0.5)
                                                                                                                                                                  and ((filesize > 287642.0)
                                                                                                                                                                    and ((#s293 <= 0.5)
                                                                                                                                                                      and ((#s604 <= 0.5)
                                                                                                                                                                        and ((#s164 <= 2.0)
                                                                                                                                                                          and ((#s151 <= 1.5)
                                                                                                                                                                            and ((#s225 <= 0.5)
                                                                                                                                                                              and ((filesize <= 298354.0)
                                                                                                                                                                              )))))))))))))))))))) or (#s601 > 1.0)
                                                                                                                                      )))) or (#s59 > 0.5)
                                                                                                                                and ((#s660 <= 0.5)
                                                                                                                                  and ((#s69 <= 2.5)
                                                                                                                                    and ((#s464 <= 0.5)
                                                                                                                                      and ((#s58 <= 0.5)
                                                                                                                                        and ((#s146 <= 0.5)
                                                                                                                                          and ((#s665 <= 0.5)
                                                                                                                                            and ((#s119 <= 0.5)
                                                                                                                                              and ((filesize <= 81666.0)
                                                                                                                                                and ((#s60 > 1.0)
                                                                                                                                                ))))))))))) or (#s440 > 1.0)
                                                                                                                          )) or (#s127 > 0.5)
                                                                                                                        and ((filesize > 538887.0)
                                                                                                                        ))) or (#s63 > 0.5)
                                                                                                                    and ((#s60 <= 0.5)
                                                                                                                      and ((#s289 <= 0.5)
                                                                                                                        and ((#s62 <= 0.5)
                                                                                                                          and ((#s689 <= 0.5)
                                                                                                                            and ((#s59 <= 0.5)
                                                                                                                              and ((#s81 <= 1.0)
                                                                                                                                and ((#s120 <= 0.5)
                                                                                                                                  and ((#s619 <= 1.0)
                                                                                                                                    and ((#s694 <= 0.5)
                                                                                                                                      and ((#s68 <= 0.5)
                                                                                                                                        and ((#s696 <= 0.5)
                                                                                                                                          and ((#s293 <= 0.5)
                                                                                                                                            and ((#s63 <= 3.0)
                                                                                                                                              and ((filesize > 586212.0)
                                                                                                                                                and ((#s701 <= 0.5)
                                                                                                                                                  and ((filesize <= 624388.0)
                                                                                                                                                  ) or (#s701 > 0.5)
                                                                                                                                                )))) or (#s696 > 0.5)
                                                                                                                                        )))))))))))) or (#s98 > 1.5)
                                                                                                                  and ((#s78 <= 0.5)
                                                                                                                    and ((#s720 <= 0.5)
                                                                                                                      and ((#s721 <= 0.5)
                                                                                                                        and ((#s132 <= 0.5)
                                                                                                                          and ((#s723 <= 2.0)
                                                                                                                            and ((#s724 <= 0.5)
                                                                                                                              and ((#s725 <= 1.5)
                                                                                                                                and ((#s63 <= 3.0)
                                                                                                                                  and ((#s120 <= 1.0)
                                                                                                                                    and ((#s68 > 1.0)
                                                                                                                                      and ((#s730 <= 1.0)
                                                                                                                                        and ((#s731 <= 0.5)
                                                                                                                                          and ((filesize <= 976710.0)
                                                                                                                                            and ((#s55 > 1.0)
                                                                                                                                            )) or (#s731 > 0.5)
                                                                                                                                        ) or (#s730 > 1.0)
                                                                                                                                      )) or (#s120 > 1.0)
                                                                                                                                  ))))))))))) or (#s149 > 0.5)
                                                                                                              and ((#s751 > 0.5)
                                                                                                                and ((#s417 > 0.5)
                                                                                                                  and ((#s755 > 0.5)
                                                                                                                  ))))))) or (#s429 > 0.5)
                                                                                                      and ((#s761 <= 0.5)
                                                                                                        and ((#s762 > 1.5)
                                                                                                        )))) or (#s46 > 0.5)
                                                                                                  and ((#s50 <= 3.5)
                                                                                                    and ((#s767 <= 0.5)
                                                                                                      and ((#s768 <= 0.5)
                                                                                                        and ((#s769 <= 0.5)
                                                                                                          and ((#s770 <= 1.0)
                                                                                                            and ((#s771 <= 0.5)
                                                                                                              and ((#s772 <= 0.5)
                                                                                                                and ((#s773 <= 0.5)
                                                                                                                  and ((#s774 <= 0.5)
                                                                                                                    and ((#s775 <= 0.5)
                                                                                                                      and ((#s776 <= 0.5)
                                                                                                                        and ((#s755 <= 0.5)
                                                                                                                          and ((#s418 <= 0.5)
                                                                                                                            and ((#s779 <= 0.5)
                                                                                                                              and ((#s291 <= 0.5)
                                                                                                                                and ((#s296 <= 0.5)
                                                                                                                                  and ((#s782 <= 0.5)
                                                                                                                                    and ((#s783 <= 0.5)
                                                                                                                                      and ((#s120 <= 0.5)
                                                                                                                                        and ((#s785 <= 1.0)
                                                                                                                                          and ((#s476 <= 1.5)
                                                                                                                                            and ((#s787 <= 0.5)
                                                                                                                                              and ((#s299 <= 0.5)
                                                                                                                                                and ((#s180 <= 0.5)
                                                                                                                                                  and ((#s74 <= 0.5)
                                                                                                                                                    and ((filesize <= 16520.0)
                                                                                                                                                      and ((#s53 <= 1.5)
                                                                                                                                                        and ((filesize > 14976.0)
                                                                                                                                                        )) or (filesize > 16520.0)
                                                                                                                                                      and ((#s431 <= 0.5)
                                                                                                                                                        and ((#s63 <= 0.5)
                                                                                                                                                          and ((#s799 <= 0.5)
                                                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                                                              and ((#s481 <= 1.0)
                                                                                                                                                                and ((#s251 <= 1.0)
                                                                                                                                                                  and ((#s218 <= 1.0)
                                                                                                                                                                    and ((#s53 <= 3.0)
                                                                                                                                                                      and ((#s164 <= 1.0)
                                                                                                                                                                        and ((#s806 <= 0.5)
                                                                                                                                                                          and ((#s293 <= 0.5)
                                                                                                                                                                            and ((#s48 <= 0.5)
                                                                                                                                                                              and ((#s461 <= 0.5)
                                                                                                                                                                                and ((#s810 <= 0.5)
                                                                                                                                                                                  and ((#s53 > 1.5)
                                                                                                                                                                                    and ((#s813 <= 0.5)
                                                                                                                                                                                      and ((#s458 <= 0.5)
                                                                                                                                                                                        and ((#s815 <= 0.5)
                                                                                                                                                                                          and ((#s165 <= 0.5)
                                                                                                                                                                                            and ((#s70 <= 1.5)
                                                                                                                                                                                              and ((#s71 <= 4.0)
                                                                                                                                                                                                and ((#s157 <= 0.5)
                                                                                                                                                                                                  and ((#s64 <= 1.0)
                                                                                                                                                                                                    and ((#s289 <= 0.5)
                                                                                                                                                                                                      and ((#s1 <= 1.0)
                                                                                                                                                                                                        and ((#s153 <= 2.0)
                                                                                                                                                                                                          and ((#s50 <= 1.0)
                                                                                                                                                                                                            and ((filesize <= 23920.0)
                                                                                                                                                                                                              and ((#s81 <= 1.0)
                                                                                                                                                                                                                and ((filesize > 23872.0)
                                                                                                                                                                                                                )))))))))) or (#s70 > 1.5)
                                                                                                                                                                                              and ((#s132 <= 0.5)
                                                                                                                                                                                                and ((#s225 <= 0.5)
                                                                                                                                                                                                  and ((#s1 <= 1.0)
                                                                                                                                                                                                    and ((#s301 <= 0.5)
                                                                                                                                                                                                      and ((#s437 <= 0.5)
                                                                                                                                                                                                        and ((#s127 <= 15.5)
                                                                                                                                                                                                          and ((#s845 <= 0.5)
                                                                                                                                                                                                            and ((filesize <= 29928.0)
                                                                                                                                                                                                            )))))))))) or (#s815 > 0.5)
                                                                                                                                                                                        ))))) or (#s461 > 0.5)
                                                                                                                                                                                and ((#s861 <= 0.5)
                                                                                                                                                                                  and ((#s862 <= 0.5)
                                                                                                                                                                                    and ((#s303 <= 1.0)
                                                                                                                                                                                      and ((#s619 <= 1.5)
                                                                                                                                                                                        and ((#s437 <= 1.0)
                                                                                                                                                                                          and ((#s140 <= 1.0)
                                                                                                                                                                                            and ((#s53 > 1.5)
                                                                                                                                                                                              and ((#s70 <= 0.5)
                                                                                                                                                                                                and ((#s165 > 0.5)
                                                                                                                                                                                                )))))))))) or (#s48 > 0.5)
                                                                                                                                                                              and ((#s287 <= 0.5)
                                                                                                                                                                                and ((#s51 <= 0.5)
                                                                                                                                                                                  and ((#s882 <= 0.5)
                                                                                                                                                                                    and ((#s445 <= 0.5)
                                                                                                                                                                                      and ((#s53 > 1.5)
                                                                                                                                                                                        and ((#s458 > 0.5)
                                                                                                                                                                                        ))))))))))))))))))))))) or (#s476 > 1.5)
                                                                                                                                            and ((#s301 <= 1.0)
                                                                                                                                              and ((#s146 > 0.5)
                                                                                                                                              ))) or (#s785 > 1.0)
                                                                                                                                        )) or (#s783 > 0.5)
                                                                                                                                    ) or (#s782 > 0.5)
                                                                                                                                  )) or (#s291 > 0.5)
                                                                                                                                and ((#s53 <= 1.5)
                                                                                                                                  or (#s53 > 1.5)
                                                                                                                                  and ((#s484 <= 0.5)
                                                                                                                                    and ((#s65 <= 1.0)
                                                                                                                                      and ((#s77 <= 1.0)
                                                                                                                                        and ((#s63 <= 1.0)
                                                                                                                                          and ((#s70 <= 1.0)
                                                                                                                                            and ((#s497 <= 1.0)
                                                                                                                                              and ((#s862 <= 0.5)
                                                                                                                                                and ((#s53 <= 3.0)
                                                                                                                                                  and ((#s56 <= 1.0)
                                                                                                                                                    and ((#s151 <= 0.5)
                                                                                                                                                      and ((#s74 <= 1.0)
                                                                                                                                                        and ((#s301 <= 0.5)
                                                                                                                                                          and ((#s180 <= 0.5)
                                                                                                                                                            and ((filesize <= 29080.0)
                                                                                                                                                              or (filesize > 29080.0)
                                                                                                                                                              and ((#s120 <= 0.5)
                                                                                                                                                                and ((#s287 <= 0.5)
                                                                                                                                                                  and ((filesize <= 76352.0)
                                                                                                                                                                    and ((filesize > 59193.0)
                                                                                                                                                                    ))))))))))))))))))))))) or (#s776 > 0.5)
                                                                                                                      ) or (#s775 > 0.5)
                                                                                                                      and ((#s961 > 0.5)
                                                                                                                      )) or (#s774 > 0.5)
                                                                                                                    and ((#s964 <= 2.0)
                                                                                                                      and ((#s59 <= 1.0)
                                                                                                                        and ((#s419 <= 0.5)
                                                                                                                          and ((#s57 <= 0.5)
                                                                                                                          )) or (#s59 > 1.0)
                                                                                                                        and ((#s49 <= 1.0)
                                                                                                                          and ((#s972 <= 1.0)
                                                                                                                          ))))) or (#s773 > 0.5)
                                                                                                                ) or (#s772 > 0.5)
                                                                                                              ) or (#s771 > 0.5)
                                                                                                            ) or (#s770 > 1.0)
                                                                                                            and ((#s132 <= 0.5)
                                                                                                            )) or (#s769 > 0.5)
                                                                                                        ) or (#s768 > 0.5)
                                                                                                      ) or (#s767 > 0.5)
                                                                                                      and ((#s65 <= 1.5)
                                                                                                        and ((#s986 <= 1.0)
                                                                                                        ) or (#s65 > 1.5)
                                                                                                      )) or (#s50 > 3.5)
                                                                                                  )) or (#s45 > 0.5)
                                                                                              )) or (#s43 > 0.5)
                                                                                            and ((#s418 > 0.5)
                                                                                            )) or (#s42 > 0.5)
                                                                                        ) or (#s41 > 0.5)
                                                                                        and ((#s997 <= 0.5)
                                                                                          and ((#s420 <= 0.5)
                                                                                            and ((#s64 <= 0.5)
                                                                                              and ((#s419 <= 0.5)
                                                                                                and ((#s150 <= 0.5)
                                                                                                  and ((#s58 <= 0.5)
                                                                                                    and ((#s1003 > 1.5)
                                                                                                      and ((#s624 <= 1.0)
                                                                                                        and ((#s46 > 0.5)
                                                                                                        ))) or (#s58 > 0.5)
                                                                                                    and ((#s1010 <= 0.5)
                                                                                                      and ((#s1011 > 0.5)
                                                                                                        and ((#s1013 <= 0.5)
                                                                                                          and ((#s46 <= 0.5)
                                                                                                          )))))) or (#s419 > 0.5)
                                                                                                and ((#s1020 > 1.5)
                                                                                                ))) or (#s420 > 0.5)
                                                                                            and ((#s499 <= 1.5)
                                                                                              and ((#s1025 <= 0.5)
                                                                                                and ((#s434 <= 0.5)
                                                                                                  and ((#s145 <= 0.5)
                                                                                                    and ((#s1028 <= 0.5)
                                                                                                      and ((#s41 > 1.5)
                                                                                                        and ((#s65 <= 3.0)
                                                                                                          and ((#s67 <= 2.0)
                                                                                                            and ((#s161 <= 1.0)
                                                                                                              and ((filesize > 71580.0)
                                                                                                              )))))))) or (#s1025 > 0.5)
                                                                                                and ((#s272 <= 1.0)
                                                                                                  and ((#s150 <= 0.5)
                                                                                                  ))) or (#s499 > 1.5)
                                                                                              and ((#s58 <= 1.5)
                                                                                                and ((#s272 <= 2.0)
                                                                                                )))) or (#s997 > 0.5)
                                                                                        )) or (#s40 > 0.5)
                                                                                    ) or (#s39 > 0.5)
                                                                                  ) or (#s38 > 1.0)
                                                                                ) or (#s37 > 0.5)
                                                                              ) or (#s36 > 0.5)
                                                                            ) or (#s35 > 0.5)
                                                                            and ((#s149 <= 0.5)
                                                                              and ((#s1060 <= 0.5)
                                                                                and ((#s1061 <= 1.0)
                                                                                  and ((#s418 <= 0.5)
                                                                                    and ((#s74 <= 1.0)
                                                                                      and ((#s291 > 0.5)
                                                                                        and ((#s1066 <= 0.5)
                                                                                          and ((filesize > 58800.0)
                                                                                          ) or (#s1066 > 0.5)
                                                                                        )))))))) or (#s34 > 0.5)
                                                                          and ((#s1076 <= 2.5)
                                                                            and ((#s303 <= 2.5)
                                                                              and ((#s1078 <= 0.5)
                                                                                and ((filesize <= 76784.0)
                                                                                  and ((#s133 <= 0.5)
                                                                                    and ((#s418 <= 0.5)
                                                                                      and ((#s48 <= 0.5)
                                                                                        and ((#s304 <= 1.0)
                                                                                          and ((#s431 <= 0.5)
                                                                                            and ((#s64 > 1.0)
                                                                                              and ((#s53 <= 1.5)
                                                                                                and ((#s1088 <= 0.5)
                                                                                                  and ((filesize > 74632.0)
                                                                                                  ))))))))))) or (#s303 > 2.5)
                                                                              and ((#s1101 <= 1.5)
                                                                                and ((filesize <= 102168.0)
                                                                                ))) or (#s1076 > 2.5)
                                                                          )) or (#s33 > 0.5)
                                                                      ) or (#s32 > 1.5)
                                                                      and ((#s1108 <= 0.5)
                                                                        and ((#s63 <= 3.5)
                                                                          and ((#s1110 <= 0.5)
                                                                            and ((#s755 <= 0.5)
                                                                              and ((#s1112 <= 0.5)
                                                                                and ((#s1113 <= 1.5)
                                                                                  and ((#s1114 <= 1.5)
                                                                                    and ((#s1115 <= 0.5)
                                                                                      and ((#s50 <= 1.5)
                                                                                        and ((#s44 <= 1.5)
                                                                                          and ((#s1118 <= 0.5)
                                                                                            and ((#s71 <= 1.0)
                                                                                              and ((#s55 <= 1.0)
                                                                                                and ((#s251 <= 0.5)
                                                                                                  and ((#s59 <= 1.0)
                                                                                                    and ((#s1 <= 1.0)
                                                                                                      and ((#s268 <= 0.5)
                                                                                                        and ((#s46 <= 0.5)
                                                                                                          and ((#s32 <= 2.5)
                                                                                                            and ((#s1127 <= 1.0)
                                                                                                              and ((#s41 <= 0.5)
                                                                                                                and ((#s419 <= 0.5)
                                                                                                                  and ((#s779 <= 0.5)
                                                                                                                    and ((#s287 <= 0.5)
                                                                                                                      and ((#s74 <= 1.0)
                                                                                                                        and ((#s1133 <= 0.5)
                                                                                                                          and ((#s1134 <= 0.5)
                                                                                                                            and ((#s63 <= 1.0)
                                                                                                                              and ((#s50 <= 0.5)
                                                                                                                                and ((#s420 <= 0.5)
                                                                                                                                  and ((#s53 <= 0.5)
                                                                                                                                    and ((#s294 <= 0.5)
                                                                                                                                      and ((#s70 <= 1.0)
                                                                                                                                        and ((#s9 <= 0.5)
                                                                                                                                          and ((#s165 <= 0.5)
                                                                                                                                            and ((#s120 <= 1.0)
                                                                                                                                              and ((#s164 <= 0.5)
                                                                                                                                                and ((#s1145 <= 0.5)
                                                                                                                                                  and ((#s431 <= 0.5)
                                                                                                                                                    and ((#s180 > 0.5)
                                                                                                                                                      and ((#s301 > 1.0)
                                                                                                                                                      )))))))))))))))))))))))))) or (#s59 > 1.0)
                                                                                                    and ((#s1176 <= 0.5)
                                                                                                      and ((#s49 > 1.0)
                                                                                                      )))))) or (#s1118 > 0.5)
                                                                                            and ((#s761 <= 1.0)
                                                                                              and ((#s1185 <= 0.5)
                                                                                                and ((#s1186 <= 0.5)
                                                                                                  and ((#s182 <= 0.5)
                                                                                                    and ((#s418 <= 0.5)
                                                                                                    )))))) or (#s44 > 1.5)
                                                                                          and ((#s165 <= 0.5)
                                                                                            and ((#s35 <= 0.5)
                                                                                              and ((#s813 <= 0.5)
                                                                                                and ((#s1198 <= 0.5)
                                                                                                  and ((#s53 <= 0.5)
                                                                                                    and ((#s458 <= 0.5)
                                                                                                      and ((filesize > 2106278.0)
                                                                                                      )))))))) or (#s50 > 1.5)
                                                                                        and ((#s149 > 0.5)
                                                                                          and ((filesize <= 78202.0)
                                                                                            and ((#s1198 <= 0.5)
                                                                                              and ((#s160 <= 0.5)
                                                                                                and ((#s70 <= 1.0)
                                                                                                  and ((#s458 > 0.5)
                                                                                                    and ((filesize > 56286.0)
                                                                                                    ))))) or (filesize > 78202.0)
                                                                                            and ((#s1224 <= 0.5)
                                                                                              and ((#s1225 > 0.5)
                                                                                              ))))) or (#s1115 > 0.5)
                                                                                      and ((#s1229 <= 0.5)
                                                                                      )) or (#s1114 > 1.5)
                                                                                    and ((#s1232 <= 1.0)
                                                                                      and ((#s41 > 1.5)
                                                                                        and ((#s1235 <= 1.0)
                                                                                          and ((#s1236 <= 4.5)
                                                                                          ))))) or (#s1113 > 1.5)
                                                                                  and ((#s494 <= 0.5)
                                                                                    and ((#s119 <= 0.5)
                                                                                      and ((#s132 > 0.5)
                                                                                        and ((#s751 <= 1.0)
                                                                                          and ((#s65 > 1.5)
                                                                                          )))))) or (#s1112 > 0.5)
                                                                                and ((#s1252 <= 1.0)
                                                                                  and ((#s431 <= 1.5)
                                                                                    and ((#s458 <= 0.5)
                                                                                      and ((#s1255 <= 0.5)
                                                                                        and ((#s1256 > 0.5)
                                                                                        )))) or (#s1252 > 1.0)
                                                                                )) or (#s755 > 0.5)
                                                                              and ((#s1263 <= 0.5)
                                                                                and ((#s46 > 0.5)
                                                                                  and ((filesize <= 678148.0)
                                                                                  )))) or (#s1110 > 0.5)
                                                                            and ((#s1114 <= 0.5)
                                                                            )) or (#s63 > 3.5)
                                                                          and ((#s41 > 1.5)
                                                                            and ((#s1275 > 1.0)
                                                                              and ((#s1224 <= 1.0)
                                                                              )))) or (#s1108 > 0.5)
                                                                      )) or (#s31 > 1.0)
                                                                  ) or (#s30 > 0.5)
                                                                ) or (#s29 > 1.0)
                                                                and ((#s63 > 1.0)
                                                                )) or (#s28 > 0.5)
                                                            ) or (#s27 > 0.5)
                                                          ) or (#s26 > 0.5)
                                                        ) or (#s25 > 0.5)
                                                      ) or (#s24 > 1.0)
                                                    ) or (#s23 > 1.0)
                                                  ) or (#s22 > 4.0)
                                                ) or (#s21 > 0.5)
                                              ) or (#s20 > 0.5)
                                            ) or (#s19 > 0.5)
                                          ) or (#s18 > 1.5)
                                          and ((#s32 <= 1.0)
                                            and ((#s299 <= 0.5)
                                              and ((#s1127 > 1.0)
                                              )))) or (#s17 > 0.5)
                                      ) or (#s16 > 0.5)
                                    ) or (#s15 > 0.5)
                                  ) or (#s14 > 0.5)
                                  and ((#s1306 <= 0.5)
                                    and ((#s14 <= 1.5)
                                      and ((#s1308 <= 0.5)
                                        and ((filesize <= 7578068.0)
                                        )) or (#s14 > 1.5)
                                    ))) or (#s13 > 0.5)
                              ) or (#s12 > 0.5)
                              and ((#s434 <= 0.5)
                                and ((#s1317 <= 0.5)
                                  and ((#s1318 <= 1.5)
                                    and ((#s132 <= 0.5)
                                      and ((#s1320 <= 0.5)
                                        and ((#s1321 <= 0.5)
                                          and ((#s1322 <= 0.5)
                                            and ((#s1323 <= 0.5)
                                              and ((#s810 > 0.5)
                                                and ((#s1326 <= 0.5)
                                                  and ((#s53 <= 1.0)
                                                    and ((#s153 > 1.0)
                                                    ))))) or (#s1322 > 0.5)
                                          ) or (#s1321 > 0.5)
                                          and ((#s1335 > 0.5)
                                            and ((#s419 <= 0.5)
                                            ))) or (#s1320 > 0.5)
                                        and ((#s1340 > 0.5)
                                        )) or (#s132 > 0.5)
                                      and ((#s1343 <= 0.5)
                                        and ((#s294 <= 0.5)
                                          and ((#s146 <= 0.5)
                                            and ((#s1346 <= 5.5)
                                              and ((#s16 <= 0.5)
                                                and ((#s65 <= 3.0)
                                                  and ((filesize <= 184058.0)
                                                    or (filesize > 184058.0)
                                                    and ((#s132 > 2.5)
                                                    )) or (#s65 > 3.0)
                                                ) or (#s16 > 0.5)
                                              )) or (#s146 > 0.5)
                                            and ((#s57 <= 0.5)
                                              or (#s57 > 0.5)
                                              and ((#s1185 <= 0.5)
                                                and ((#s46 > 0.5)
                                                  and ((#s1362 <= 5.5)
                                                  )) or (#s1185 > 0.5)
                                              ))) or (#s294 > 0.5)
                                          and ((#s1366 > 0.5)
                                          )))) or (#s1318 > 1.5)
                                  )) or (#s434 > 0.5)
                                and ((#s65 <= 0.5)
                                  and ((#s418 > 0.5)
                                  ) or (#s65 > 0.5)
                                  and ((#s32 <= 1.0)
                                    and ((#s1362 <= 0.5)
                                      and ((#s31 <= 0.5)
                                        and ((#s270 <= 0.5)
                                          and ((#s751 <= 0.5)
                                            and ((#s160 <= 0.5)
                                            ) or (#s751 > 0.5)
                                            and ((#s660 > 1.0)
                                            ))) or (#s31 > 0.5)
                                      ) or (#s1362 > 0.5)
                                      and ((#s1389 > 1.5)
                                      )) or (#s32 > 1.0)
                                    and ((#s180 <= 0.5)
                                      and ((#s272 <= 1.0)
                                      )))))) or (#s11 > 0.5)
                          ) or (#s10 > 1.5)
                          and ((#s1113 <= 3.5)
                          )) or (#s9 > 2.5)
                        and ((#s1118 <= 1.0)
                          and ((#s1402 > 1.0)
                          ))) or (#s8 > 0.5)
                    ) or (#s7 > 0.5)
                  ) or (#s6 > 0.5)
                ) or (#s5 > 2.5)
                and ((#s1409 <= 0.5)
                )) or (#s4 > 0.5)
              and ((#s751 > 0.5)
                and ((#s1414 <= 0.5)
                  and ((#s1346 <= 1.5)
                    and ((#s1416 <= 1.0)
                      and ((#s1013 <= 0.5)
                        and ((#s1418 <= 1.5)
                          or (#s1418 > 1.5)
                          and ((#s1420 <= 0.5)
                            and ((#s299 <= 0.5)
                              and ((#s1422 <= 1.0)
                                and ((#s31 <= 1.0)
                                  and ((#s1424 <= 0.5)
                                    and ((#s1425 <= 1.0)
                                      and ((#s779 <= 0.5)
                                        and ((#s132 <= 0.5)
                                          or (#s132 > 0.5)
                                          and ((#s294 <= 1.0)
                                            and ((#s1430 <= 0.5)
                                              and ((#s70 <= 3.0)
                                                and ((#s1011 <= 0.5)
                                                  and ((#s145 <= 1.5)
                                                    and ((#s1434 <= 0.5)
                                                      and ((#s268 <= 0.5)
                                                        and ((#s165 <= 0.5)
                                                          and ((#s1437 > 1.0)
                                                            and ((#s59 > 2.0)
                                                              and ((#s64 > 2.0)
                                                                and ((#s1133 <= 0.5)
                                                                  and ((#s53 <= 1.0)
                                                                  ))))))) or (#s1434 > 0.5)
                                                    )) or (#s1011 > 0.5)
                                                  and ((#s458 > 0.5)
                                                    and ((#s49 <= 1.0)
                                                    ))))))) or (#s779 > 0.5)
                                        and ((#s458 <= 0.5)
                                          and ((#s165 <= 0.5)
                                            and ((#s1462 <= 0.5)
                                              and ((#s157 <= 0.5)
                                                and ((#s1402 <= 0.5)
                                                  and ((#s1465 > 0.5)
                                                  ))) or (#s1462 > 0.5)
                                              and ((#s1470 <= 0.5)
                                              ))) or (#s458 > 0.5)
                                          and ((#s1470 <= 0.5)
                                            and ((#s445 <= 1.5)
                                            )))) or (#s1425 > 1.0)
                                    ) or (#s1424 > 0.5)
                                    and ((#s60 <= 1.0)
                                      and ((#s418 <= 0.5)
                                      ))) or (#s31 > 1.0)
                                ) or (#s1422 > 1.0)
                              ) or (#s299 > 0.5)
                              and ((#s160 <= 1.5)
                                and ((#s445 <= 0.5)
                                  and ((#s153 <= 1.0)
                                    and ((#s1430 > 0.5)
                                    ) or (#s153 > 1.0)
                                  )) or (#s160 > 1.5)
                                and ((#s1495 <= 0.5)
                                  and ((#s182 <= 0.5)
                                  ) or (#s1495 > 0.5)
                                ))) or (#s1420 > 0.5)
                          )) or (#s1013 > 0.5)
                        and ((#s1 <= 1.0)
                          and ((#s1127 <= 1.0)
                            and ((#s65 <= 1.0)
                              or (#s65 > 1.0)
                              and ((#s420 <= 0.5)
                                and ((#s1470 <= 0.5)
                                  and ((#s1025 > 1.0)
                                  ) or (#s1470 > 0.5)
                                  and ((#s762 > 1.0)
                                  )) or (#s420 > 0.5)
                              )) or (#s1127 > 1.0)
                          ) or (#s1 > 1.0)
                        ))) or (#s1346 > 1.5)
                    and ((#s275 <= 1.0)
                      and ((#s167 <= 0.5)
                        and ((#s1519 <= 1.0)
                          and ((#s419 <= 1.5)
                            and ((#s446 <= 0.5)
                              and ((#s431 <= 1.0)
                                and ((#s1127 <= 1.0)
                                  and ((#s477 <= 0.5)
                                  ) or (#s1127 > 1.0)
                                ) or (#s431 > 1.0)
                              ) or (#s446 > 0.5)
                              and ((#s1028 > 0.5)
                                and ((#s1430 > 0.5)
                                ))))) or (#s167 > 0.5)
                        and ((#s1127 <= 1.5)
                          and ((#s1346 <= 3.5)
                            and ((#s304 <= 2.0)
                              or (#s304 > 2.0)
                              and ((#s1540 > 0.5)
                              ))) or (#s1127 > 1.5)
                          and ((#s484 <= 1.0)
                            and ((#s1176 <= 0.5)
                              and ((#s9 <= 1.0)
                              ))))))) or (#s1414 > 0.5)
                ))) or (#s3 > 1.0)
            and ((#s1553 <= 3.0)
            )) or (#s2 > 0.5)
          and ((#s1028 <= 0.5)
            and ((#s1557 <= 0.5)
              and ((#s160 <= 1.5)
                and ((#s1559 <= 0.5)
                  and ((#s498 <= 0.5)
                    and ((#s770 <= 1.0)
                      and ((#s1562 <= 1.0)
                        and ((#s65 <= 1.5)
                          and ((#s1564 > 0.5)
                            and ((#s1366 > 0.5)
                              and ((filesize <= 10092017.0)
                              ))) or (#s65 > 1.5)
                          and ((#s1118 <= 0.5)
                            and ((#s1572 > 0.5)
                              and ((#s133 <= 0.5)
                                and ((#s1575 <= 0.5)
                                ))))) or (#s1562 > 1.0)
                      ) or (#s770 > 1.0)
                    ) or (#s498 > 0.5)
                    and ((#s1582 <= 0.5)
                      and ((#s1306 <= 0.5)
                        and ((#s1584 <= 1.0)
                          and ((#s132 <= 0.5)
                          ))) or (#s1582 > 0.5)
                    ))) or (#s160 > 1.5)
                and ((#s1592 > 1.5)
                  and ((#s299 > 1.0)
                  ))) or (#s1557 > 0.5)
              and ((#s1597 <= 0.5)
                and ((#s751 <= 0.5)
                  and ((#s720 > 1.5)
                  )))) or (#s1028 > 0.5)
            and ((#s1604 <= 0.5)
              and ((#s1605 <= 0.5)
                and ((#s1606 > 0.5)
                  and ((#s1608 <= 1.0)
                    and ((#s1609 <= 0.5)
                      and ((#s1335 <= 0.5)
                      ) or (#s1609 > 0.5)
                      and ((#s5 <= 12.0)
                      )) or (#s1608 > 1.0)
                  ))) or (#s1604 > 0.5)
            ))) or (#s1 > 3.0)
        and ((#s481 <= 1.5)
          and ((#s1620 <= 0.5)
            and ((#s1621 <= 2.5)
              and ((#s81 <= 1.0)
                and ((#s484 > 0.5)
                  and ((#s1625 > 0.5)
                    and ((#s1627 <= 0.5)
                    ))) or (#s81 > 1.0)
                and ((#s117 > 0.5)
                )) or (#s1621 > 2.5)
            ) or (#s1620 > 0.5)
          ) or (#s481 > 1.5)
          and ((#s445 <= 0.5)
            and ((#s1232 <= 0.5)
              and ((#s71 <= 1.0)
                and ((#s301 <= 1.0)
                  and ((#s218 > 1.0)
                    and ((#s464 > 1.0)
                      and ((#s287 <= 0.5)
                        and ((filesize <= 1122944.0)
                        )))) or (#s301 > 1.0)
                  and ((#s1186 <= 1.0)
                    and ((#s67 <= 1.0)
                      and ((#s294 <= 1.0)
                        and ((filesize <= 503542.0)
                        ))))) or (#s71 > 1.0)
                and ((#s289 <= 1.0)
                  and ((#s180 <= 1.5)
                    and ((#s1659 <= 1.0)
                      and ((#s1660 <= 0.5)
                        and ((#s1661 <= 0.5)
                          and ((#s1662 <= 6.0)
                            and ((#s48 <= 0.5)
                              and ((#s1664 > 0.5)
                              )))) or (#s1660 > 0.5)
                      ) or (#s1659 > 1.0)
                    ) or (#s180 > 1.5)
                    and ((#s1672 <= 2.5)
                      and ((#s1673 <= 1.0)
                      ) or (#s1672 > 2.5)
                    )) or (#s289 > 1.0)
                )) or (#s1232 > 0.5)
              and ((#s810 <= 1.5)
                and ((#s488 <= 1.0)
                  and ((#s1680 <= 0.5)
                    or (#s1680 > 0.5)
                    and ((#s1236 <= 1.0)
                      and ((#s50 <= 2.5)
                        and ((#s14 <= 2.5)
                          and ((filesize <= 19809960.0)
                          ) or (#s14 > 2.5)
                        ) or (#s50 > 2.5)
                        and ((#s77 > 59.0)
                        )) or (#s1236 > 1.0)
                      and ((#s1559 <= 0.5)
                        and ((#s1693 <= 0.5)
                          or (#s1693 > 0.5)
                          and ((filesize > 7098608.0)
                          )) or (#s1559 > 0.5)
                      ))) or (#s488 > 1.0)
                  and ((filesize > 18004136.0)
                  )) or (#s810 > 1.5)
                and ((#s1702 > 3.5)
                  and ((#s1704 <= 3.0)
                    and ((#s1705 <= 24.0)
                      and ((filesize <= 17175080.0)
                      ) or (#s1705 > 24.0)
                    ) or (#s1704 > 3.0)
                    and ((#s140 <= 2.0)
                      and ((#s14 <= 2.5)
                        and ((#s730 > 1.0)
                        ) or (#s14 > 2.5)
                      ) or (#s140 > 2.0)
                      and ((filesize > 25131176.0)
                        and ((filesize <= 25131192.0)
                        ))))))) or (#s445 > 0.5)
            and ((#s160 <= 0.5)
              and ((#s70 > 1.0)
                and ((#s120 <= 1.5)
                  and ((filesize <= 27684066.0)
                    and ((#s1726 <= 1.0)
                      and ((#s494 <= 1.0)
                        and ((#s1621 <= 1.5)
                          and ((#s1673 <= 0.5)
                            and ((#s600 <= 1.0)
                              and ((#s484 <= 1.5)
                                and ((#s476 <= 1.0)
                                  and ((#s1625 > 0.5)
                                    and ((#s1735 > 0.5)
                                    )) or (#s476 > 1.0)
                                )) or (#s600 > 1.0)
                              and ((#s287 <= 0.5)
                                or (#s287 > 0.5)
                                and ((#s1742 > 0.5)
                                ))) or (#s1673 > 0.5)
                          ) or (#s1621 > 1.5)
                        )))) or (#s120 > 1.5)
                  and ((#s1750 <= 0.5)
                    and ((#s1672 > 1.0)
                      and ((#s1753 > 1.0)
                      )) or (#s1750 > 0.5)
                  ))))))) or (#s0 > 0.5)
      and ((#s420 <= 0.5)
        and ((#s1127 <= 0.5)
          and ((#s304 <= 0.5)
            and ((#s1761 > 0.5)
              and ((#s1362 <= 1.5)
                and ((#s1764 > 0.5)
                  and ((#s1766 <= 9.0)
                  )))) or (#s304 > 0.5)
            and ((#s1770 <= 0.5)
              and ((#s1771 <= 1.0)
                and ((#s476 <= 3.0)
                  and ((#s1366 <= 0.5)
                    and ((#s1774 <= 1.0)
                      and ((#s1775 <= 1.5)
                        and ((#s1776 <= 1.0)
                          and ((#s1777 <= 1.5)
                            and ((#s268 > 0.5)
                              and ((#s779 <= 0.5)
                                and ((#s268 <= 1.5)
                                  and ((#s1255 <= 0.5)
                                    and ((#s1783 <= 0.5)
                                      and ((#s63 <= 1.0)
                                        and ((#s418 > 0.5)
                                          and ((#s53 > 1.5)
                                            and ((#s1789 > 0.5)
                                            )))))))))) or (#s1776 > 1.0)
                          and ((#s779 > 0.5)
                            and ((#s465 <= 0.5)
                              and ((filesize <= 209960.0)
                              ) or (#s465 > 0.5)
                              and ((filesize <= 105608.0)
                              )))) or (#s1775 > 1.5)
                        and ((#s1807 <= 1.5)
                          and ((#s1808 <= 1.0)
                            and ((#s964 <= 1.0)
                              and ((#s1810 <= 5.5)
                                and ((#s774 > 0.5)
                                  and ((#s1813 <= 0.5)
                                  )) or (#s1810 > 5.5)
                                and ((filesize <= 132606.0)
                                  and ((#s182 <= 0.5)
                                    and ((#s1818 <= 0.5)
                                      and ((#s53 <= 1.5)
                                        and ((#s1820 <= 1.0)
                                          and ((#s1821 > 0.5)
                                          ) or (#s1820 > 1.0)
                                        ) or (#s53 > 1.5)
                                        and ((#s64 <= 2.0)
                                          and ((#s1826 <= 1.0)
                                            and ((#s1389 <= 0.5)
                                              and ((#s41 <= 0.5)
                                                and ((#s434 <= 4.0)
                                                  and ((#s65 <= 1.0)
                                                    and ((#s291 > 0.5)
                                                    )))))) or (#s64 > 2.0)
                                          and ((#s304 <= 2.0)
                                            and ((#s268 <= 0.5)
                                              and ((#s1841 <= 1.0)
                                              ) or (#s268 > 0.5)
                                            )))) or (#s1818 > 0.5)
                                    ) or (#s182 > 0.5)
                                    and ((#s806 <= 1.0)
                                      and ((filesize > 61522.0)
                                      ) or (#s806 > 1.0)
                                    )) or (filesize > 132606.0)
                                  and ((#s1462 <= 0.5)
                                    and ((#s1597 <= 1.0)
                                      and ((#s457 <= 0.5)
                                        and ((#s304 <= 2.0)
                                          and ((#s77 <= 4.5)
                                            and ((#s1025 <= 1.0)
                                              and ((#s32 > 1.0)
                                                and ((#s1256 > 0.5)
                                                ))) or (#s77 > 4.5)
                                            and ((#s1864 > 0.5)
                                            )) or (#s304 > 2.0)
                                          and ((#s1867 > 1.0)
                                          )) or (#s457 > 0.5)
                                        and ((#s1870 > 1.5)
                                          and ((#s304 > 2.0)
                                          )))) or (#s1462 > 0.5)
                                    and ((#s1876 <= 0.5)
                                      and ((#s56 <= 1.0)
                                        and ((#s160 > 0.5)
                                          and ((#s1693 <= 0.5)
                                            and ((#s157 <= 0.5)
                                            ) or (#s1693 > 0.5)
                                          ))) or (#s1876 > 0.5)
                                    )))) or (#s964 > 1.0)
                              and ((#s964 <= 3.0)
                                and ((#s1888 <= 1.0)
                                  and ((#s1889 > 0.5)
                                  ) or (#s1888 > 1.0)
                                )))))) or (#s1774 > 1.0)
                    ) or (#s1366 > 0.5)
                    and ((#s1726 > 1.0)
                      and ((#s1899 > 1.5)
                        and ((#s1901 > 1.0)
                          and ((#s1808 <= 24.0)
                            and ((#s779 > 0.5)
                              and ((filesize <= 545808.0)
                                and ((filesize > 541744.0)
                                ))))))))) or (#s1771 > 1.0)
              ) or (#s1770 > 0.5)
            )) or (#s1127 > 0.5)
          and ((#s1559 > 2.5)
            and ((#s1112 <= 0.5)
              and ((#s291 <= 0.5)
                and ((#s299 <= 0.5)
                  and ((#s119 <= 0.5)
                    and ((#s1127 <= 1.5)
                    ) or (#s119 > 0.5)
                  ) or (#s299 > 0.5)
                  and ((#s1925 <= 1.0)
                    and ((#s600 <= 1.0)
                    ))) or (#s291 > 0.5)
              ) or (#s1112 > 0.5)
              and ((#s1864 <= 0.5)
              )))) or (#s420 > 0.5)
        and ((#s1934 <= 0.5)
          and ((#s1326 <= 1.0)
            and ((#s1936 <= 0.5)
              and ((#s48 <= 0.5)
                and ((#s1938 <= 1.0)
                  and ((#s1575 <= 0.5)
                    and ((#s862 <= 0.5)
                      and ((#s1941 <= 1.0)
                        and ((#s1942 <= 1.0)
                          and ((#s1943 <= 0.5)
                            and ((#s1944 <= 1.0)
                              and ((#s301 <= 1.5)
                                and ((#s1946 <= 0.5)
                                  and ((#s12 <= 0.5)
                                    and ((#s1948 <= 4.5)
                                      and ((#s1949 <= 0.5)
                                        and ((#s1950 > 0.5)
                                        ) or (#s1949 > 0.5)
                                      )) or (#s12 > 0.5)
                                  ) or (#s1946 > 0.5)
                                )) or (#s1944 > 1.0)
                            ) or (#s1943 > 0.5)
                            and ((#s1949 > 0.5)
                              and ((#s1362 <= 2.5)
                                and ((#s1659 > 1.5)
                                )))))) or (#s862 > 0.5)
                      and ((#s150 > 0.5)
                      )))) or (#s48 > 0.5)
                and ((#s1821 <= 0.5)
                  and ((#s3 > 4.0)
                  ) or (#s1821 > 0.5)
                ))) or (#s1326 > 1.0)
            and ((#s1979 <= 0.5)
              and ((#s1980 <= 1.5)
                and ((#s303 <= 1.0)
                ) or (#s1980 > 1.5)
              ) or (#s1979 > 0.5)
              and ((#s1764 <= 0.5)
              ))) or (#s1934 > 0.5)
          and ((#s1988 > 1.0)
          ))))
}